/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include "https.h"


// ClientHello callback
int tws_ClientHelloCallback(SSL *ssl, int *al, void *arg) {

    const unsigned char *extension_data;
    size_t extension_len;
    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &extension_data, &extension_len) ||
        extension_len <= 2) {
        goto abort;
    }

    /* Extract the length of the supplied list of names. */
    const unsigned char *p = extension_data;
    size_t len;
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 != extension_len)
        goto abort;
    extension_len = len;
    /*
     * The list in practice only has a single element, so we only consider
     * the first one.
     */
    if (extension_len == 0 || *p++ != TLSEXT_NAMETYPE_host_name)
        goto abort;
    extension_len--;
    /* Now we can finally pull out the byte array with the actual hostname. */
    if (extension_len <= 2)
        goto abort;
    len = (*(p++) << 8);
    len += *(p++);
    if (len == 0 || len + 2 > extension_len || len > TLSEXT_MAXLEN_host_name
        || memchr(p, 0, len) != NULL) {
        DBG(fprintf(stderr, "extension_data is null in clienthello callback\n"));
        goto abort;
    }
    extension_len = len;
    int servername_len = len;
    const char *servername = (const char *) p;
    // "extension_data" is not null-terminated, so we need to copy it to a new buffer
    DBG(fprintf(stderr, "servername=%.*s\n", (int) len, p));

    Tcl_DString ds;
    Tcl_DStringInit(&ds);
    /* version */
    uint16_t version = SSL_version(ssl);
    char buf[6];
    snprintf(buf, sizeof(buf), "%d", version);
    Tcl_DStringAppend(&ds, buf, -1);
    Tcl_DStringAppend(&ds, ",", 1);
    /* ciphers */
    const SSL_CIPHER *cipher;
    const uint8_t *cipher_suites;
    len = SSL_client_hello_get0_ciphers(ssl, &cipher_suites);
    if (len % 2 != 0)
        goto abort;
    for (; len != 0; len -= 2, cipher_suites += 2) {
        cipher = SSL_CIPHER_find(ssl, cipher_suites);
        if (cipher) {
            DBG(fprintf(stderr, "cipher=%s\n", SSL_CIPHER_get_name(cipher)));
            uint16_t cipher_protocol_id = SSL_CIPHER_get_protocol_id(cipher);
            snprintf(buf, sizeof(buf), "%d", cipher_protocol_id);
            Tcl_DStringAppend(&ds, buf, -1);
            if (len > 2) {
                Tcl_DStringAppend(&ds, "-", 1);
            }
        }
    }
    Tcl_DStringAppend(&ds, ",", 1);

    /* extensions */
    int *out;
    size_t outlen;
    if (SSL_client_hello_get1_extensions_present(ssl, &out, &outlen)) {
        fprintf(stderr, "extslen=%zd\n", outlen);
        for (; outlen > 0; outlen--) {
            snprintf(buf, sizeof(buf), "%d", *out++);
            Tcl_DStringAppend(&ds, buf, -1);
            if (outlen > 1) {
                Tcl_DStringAppend(&ds, "-", 1);
            }
        }
    }
    Tcl_DStringAppend(&ds, ",", 1);

    /* Supported Groups (elliptic curves) */
    const unsigned char *exts;
    size_t extslen;
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_supported_groups, &exts, &extslen)) {
        if (extslen < 2)
            goto abort;
        len = (*exts++) << 8;
        len |= *exts++;
        if (len + 2 != extslen)
            goto abort;
        if (len % 2 != 0)
            goto abort;

        for (; len > 0; len -= 2) {
            uint16_t group;
            group = *exts++;
            group <<= 8;
            group |= *exts++;
            snprintf(buf, sizeof(buf), "%d", group);
            Tcl_DStringAppend(&ds, buf, -1);
            if (len > 2) {
                Tcl_DStringAppend(&ds, "-", 1);
            }
        }
    }
    Tcl_DStringAppend(&ds, ",", 1);

    /* elliptic curve point formats */
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_ec_point_formats, &exts, &extslen)) {
        if (extslen < 1)
            goto abort;
        len = *exts++;
        if (len + 1 != extslen)
            goto abort;

        for (; len > 0; len--) {
            uint8_t format = *exts++;
            snprintf(buf, sizeof(buf), "%d", format);
            Tcl_DStringAppend(&ds, buf, -1);
            if (len > 1) {
                Tcl_DStringAppend(&ds, "-", 1);
            }
        }
    }

    // firefox: 772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0
    fprintf(stderr, "ja3=%s\n", Tcl_DStringValue(&ds));
    Tcl_DStringFree(&ds);

//    /* extract/check clientHello information */
//    int has_rsa_sig = 0, has_ecdsa_sig = 0;
//    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_signature_algorithms, &extension_data, &extension_len)) {
//        uint8_t sign;
////        size_t len;
//        if (extension_len < 2)
//            goto abort;
//        len = (*extension_data++) << 8;
//        len |= *extension_data++;
//        if (len + 2 != extension_len)
//            goto abort;
//        if (len % 2 != 0)
//            goto abort;
//        for (; len > 0; len -= 2) {
//            extension_data++; /* hash */
//            sign = *extension_data++;
//            switch (sign) {
//                case TLSEXT_signature_rsa:
//                    has_rsa_sig = 1;
//                    break;
//                case TLSEXT_signature_ecdsa:
//                    has_ecdsa_sig = 1;
//                    break;
//                default:
//                    continue;
//            }
//            if (has_ecdsa_sig && has_rsa_sig)
//                break;
//        }
//    } else {
//        /* without TLSEXT_TYPE_signature_algorithms extension (< TLSv1.2) */
//        goto abort;
//    }

    SSL_CTX *ctx = tws_GetInternalFromHostName(servername);
    if (!ctx) {
        DBG(fprintf(stderr, "servername not found in clienthello callback\n"));
        goto abort;
    }

//    SSL_set_verify(ssl, SSL_CTX_get_verify_mode(ctx), NULL);
//    SSL_set_client_CA_list(ssl, SSL_dup_CA_list(SSL_CTX_get_client_CA_list(ctx)));
    SSL_set_SSL_CTX(ssl, ctx);

    return SSL_CLIENT_HELLO_SUCCESS;

    abort:
    *al = SSL_AD_UNRECOGNIZED_NAME;
    return SSL_CLIENT_HELLO_ERROR;
}


int tws_CreateSslContext(Tcl_Interp *interp, SSL_CTX **sslCtx) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        SetResult("Unable to create SSL context");
        return TCL_ERROR;
    }

    unsigned long op = SSL_OP_ALL;
    op |= SSL_OP_NO_SSLv2;
    op |= SSL_OP_NO_SSLv3;
    op |= SSL_OP_NO_TLSv1;
    op |= SSL_OP_NO_TLSv1_1;
    SSL_CTX_set_options(ctx, op);

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_read_ahead(ctx, 1);

    *sslCtx = ctx;
    return TCL_OK;
}

int tws_ConfigureSslContext(Tcl_Interp *interp, SSL_CTX *ctx, const char *key_file, const char *cert_file) {
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        SetResult("Unable to load certificate");
        return TCL_ERROR;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        SetResult("Unable to load private key");
        return TCL_ERROR;
    }

    return TCL_OK;
}

int tws_ReadSslConnAsync(tws_conn_t *conn, Tcl_DString *dsPtr, int size) {
    DBG(fprintf(stderr, "ReadConn client: %d\n", conn->client));

    long max_request_read_bytes = conn->accept_ctx->server->max_request_read_bytes;
    int max_buffer_size =
            size == 0 ? conn->accept_ctx->server->max_read_buffer_size : MIN(size, conn->accept_ctx->server->max_read_buffer_size);

    char *buf = (char *) Tcl_Alloc(max_buffer_size);
    long total_read = 0;
    int rc;
    int bytes_read;

    ERR_clear_error();

    /*
     * SSL_read() may return data in parts, so try to read
     * until SSL_read() would return no data
     */

    for (;;) {
        rc = SSL_read(conn->ssl, buf, max_buffer_size);
        if (rc > 0) {
            bytes_read = rc;
            Tcl_DStringAppend(dsPtr, buf, bytes_read);
            total_read += bytes_read;
            if (total_read > max_request_read_bytes) {
                goto failed_due_to_request_too_large;
            }
            if (total_read < size) {
                continue;
            }
            if (total_read == size) {
                goto done;
            }
        } else {
            int err = SSL_get_error(conn->ssl, rc);
            if (err == SSL_ERROR_NONE) {
                goto done;
            } else if (err == SSL_ERROR_WANT_READ) {
                DBG(fprintf(stderr, "SSL_ERROR_WANT_READ\n"));
                Tcl_Free(buf);
                return TWS_AGAIN;

            } else if (err == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
                goto done;
            }

            fprintf(stderr, "SSL_read error: %s err=%d rc=%d total_read=%zd size=%d\n",
                    ssl_errors[err], err, rc, total_read, size);

            Tcl_Free(buf);
            return TWS_ERROR;
        }
        break;
    }

    Tcl_Free(buf);
    return TWS_AGAIN;

    failed_due_to_request_too_large:
    Tcl_Free(buf);
    fprintf(stderr, "request too large");
    return TWS_ERROR;

    done:
    Tcl_Free(buf);
    return TWS_DONE;

}

int tws_WriteSslConnAsync(tws_conn_t *conn, const char *buf, int len) {
    return SSL_write(conn->ssl, buf, len);
}