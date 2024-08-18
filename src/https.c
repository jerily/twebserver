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
        DBG2(printf("extension_data is null in clienthello callback\n"));
        goto abort;
    }
    extension_len = len;
    int servername_len = len;
    const char *servername = (const char *) p;
    // "extension_data" is not null-terminated, so we need to copy it to a new buffer
    DBG2(printf("servername=%.*s\n", (int) len, p));

    SSL_CTX *ctx = tws_GetInternalFromHostName(servername);
    if (!ctx) {
        DBG2(printf("servername not found in clienthello callback\n"));
        goto abort;
    }

    SSL_set_verify(ssl, SSL_CTX_get_verify_mode(ctx), NULL);
    SSL_set_client_CA_list(ssl, SSL_dup_CA_list(SSL_CTX_get_client_CA_list(ctx)));
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

int tws_ReadSslConnAsync(tws_conn_t *conn, Tcl_DString *dsPtr, Tcl_Size size) {
    DBG2(printf("ReadConn client: %d\n", conn->client));

    long max_request_read_bytes = conn->accept_ctx->server->max_request_read_bytes - Tcl_DStringLength(&conn->inout_ds);
    int max_buffer_size = MIN(INT_MAX,
            size == 0 ? conn->accept_ctx->server->max_read_buffer_size : MIN(size, conn->accept_ctx->server->max_read_buffer_size));

    char *buf = (char *) Tcl_Alloc(max_buffer_size);
    long total_read = 0;
    int rc;
    int bytes_read;

    ERR_clear_error();

    /*
     * SSL_read() may return data in parts, so try to read
     * until SSL_read() would return no data
     */

    DBG2(printf("max_buffer_size = %ld\n", max_buffer_size));

    for (;;) {
        rc = SSL_read(conn->ssl, buf, max_buffer_size);
        if (rc > 0) {
            bytes_read = rc;
            total_read += bytes_read;
            if (total_read > max_request_read_bytes) {
                goto failed_due_to_request_too_large;
            }
            Tcl_DStringAppend(dsPtr, buf, bytes_read);
            if (total_read < size) {
                continue;
            }
            if (total_read == size) {
                goto done;
            }
        } else {
            int err = SSL_get_error(conn->ssl, rc);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                DBG2(printf("AGAIN %s\n", tws_GetSslError(err)));
                Tcl_Free(buf);
                return TWS_AGAIN;

            } else if (err == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
                // peer closed connection
//                conn->shutdown = 1;
                goto done;
            }

            fprintf(stderr, "SSL_read error: %s err=%d rc=%d total_read=%zd\n",
                    tws_GetSslError(err), err, rc, total_read);

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

int tws_WriteSslConnAsync(tws_conn_t *conn, const char *buf, Tcl_Size len) {
    Tcl_Size total_written = 0;
    int rc;
    for (;;) {
        int towrite = MIN(INT_MAX, len - total_written);
        rc = SSL_write(conn->ssl, buf + total_written, towrite);
        if (rc > 0) {
            // The write operation was successful, the return value is the number
            // of bytes actually written to the TLS/SSL connection.
            total_written += rc;
            if (total_written == len) {
                return TWS_DONE;
            }
        } else {
            int err = SSL_get_error(conn->ssl, rc);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                conn->write_offset += total_written;
                return TWS_AGAIN;
            } else if (err == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
                // peer closed connection
                return TWS_DONE;
            }

            return TWS_ERROR;
        }
    }
}