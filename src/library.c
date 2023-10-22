/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#include "common.h"
#include "library.h"
#include "base64.h"
#include "uri.h"
#include "conn.h"
#include "request.h"
#include "router.h"
#include "crypto.h"

#include <sys/socket.h> // for SOMAXCONN
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>

static int tws_ModuleInitialized;

int tws_Destroy(Tcl_Interp *interp, const char *handle) {
    tws_server_t *server = tws_GetInternalFromServerName(handle);
    if (!server) {
        SetResult("server handle not found");
        return TCL_ERROR;
    }
    if (!tws_UnregisterServerName(handle)) {
        SetResult("unregister server name failed");
        return TCL_ERROR;
    }

    if (server->accept_ctx != NULL) {
        Tcl_DeleteFileHandler(server->accept_ctx->server_fd);
        Tcl_Free((char *) server->accept_ctx);
    }
    if (server->conn_thread_ids != NULL) {
        Tcl_Free((char *) server->conn_thread_ids);
    }
    Tcl_DecrRefCount(server->cmdPtr);
    if (server->scriptPtr != NULL) {
        Tcl_DecrRefCount(server->scriptPtr);
    }
    SSL_CTX_free(server->sslCtx);
    Tcl_DeleteCommand(interp, handle);
    Tcl_Free((char *) server);
    return TCL_OK;
}

static int create_context(Tcl_Interp *interp, SSL_CTX **sslCtx) {
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

static int configure_context(Tcl_Interp *interp, SSL_CTX *ctx, const char *key_file, const char *cert_file) {
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

#ifdef TWS_JA3
    /* extract/check clientHello information */
    int has_rsa_sig = 0, has_ecdsa_sig = 0;
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_signature_algorithms, &extension_data, &extension_len)) {
        uint8_t sign;
//        size_t len;
        if (extension_len < 2)
            goto abort;
        len = (*extension_data++) << 8;
        len |= *extension_data++;
        if (len + 2 != extension_len)
            goto abort;
        if (len % 2 != 0)
            goto abort;
        for (; len > 0; len -= 2) {
            extension_data++; /* hash */
            sign = *extension_data++;
            switch (sign) {
                case TLSEXT_signature_rsa:
                    has_rsa_sig = 1;
                    break;
                case TLSEXT_signature_ecdsa:
                    has_ecdsa_sig = 1;
                    break;
                default:
                    continue;
            }
            if (has_ecdsa_sig && has_rsa_sig)
                break;
        }
    } else {
        /* without TLSEXT_TYPE_signature_algorithms extension (< TLSv1.2) */
        goto abort;
    }

    // TODO: JA3 fingerprint
    const SSL_CIPHER *cipher;
    const uint8_t *cipher_suites;
    len = SSL_client_hello_get0_ciphers(ssl, &cipher_suites);
    if (len % 2 != 0)
        goto abort;
//    for (; len != 0; len -= 2, cipher_suites += 2) {
//        cipher = SSL_CIPHER_find(ssl, cipher_suites);
//        if (cipher && SSL_CIPHER_get_auth_nid(cipher) == NID_auth_ecdsa) {
//            has_ecdsa_sig = 1;
//            break;
//        }
//    }
#endif

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

static int tws_InitServerFromConfigDict(Tcl_Interp *interp, tws_server_t *server_ctx, Tcl_Obj *const configDictPtr) {
    Tcl_Obj *maxRequestReadBytesPtr;
    Tcl_Obj *maxRequestReadBytesKeyPtr = Tcl_NewStringObj("max_request_read_bytes", -1);
    Tcl_IncrRefCount(maxRequestReadBytesKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, maxRequestReadBytesKeyPtr, &maxRequestReadBytesPtr)) {
        Tcl_DecrRefCount(maxRequestReadBytesKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(maxRequestReadBytesKeyPtr);
    if (maxRequestReadBytesPtr) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, maxRequestReadBytesPtr, &server_ctx->max_request_read_bytes)) {
            SetResult("max_request_read_bytes must be an integer");
            return TCL_ERROR;
        }
    }

    // check that max_request_read_bytes is between 1 and 100MB
    if (server_ctx->max_request_read_bytes < 1 || server_ctx->max_request_read_bytes > 100 * 1024 * 1024) {
        SetResult("max_request_read_bytes must be between 1 and 100MB");
        return TCL_ERROR;
    }

    Tcl_Obj *maxReadBufferSizePtr;
    Tcl_Obj *maxReadBufferSizeKeyPtr = Tcl_NewStringObj("max_read_buffer_size", -1);
    Tcl_IncrRefCount(maxReadBufferSizeKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, maxReadBufferSizeKeyPtr, &maxReadBufferSizePtr)) {
        Tcl_DecrRefCount(maxReadBufferSizeKeyPtr);
        SetResult("error reading dict");
        return TCL_OK;
    }
    Tcl_DecrRefCount(maxReadBufferSizeKeyPtr);
    if (maxReadBufferSizePtr) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, maxReadBufferSizePtr, &server_ctx->max_read_buffer_size)) {
            SetResult("max_read_buffer_size must be an integer");
            return TCL_ERROR;
        }
    }

    // check that max_read_buffer_size is between 1 and 100MB
    if (server_ctx->max_read_buffer_size < 1 || server_ctx->max_read_buffer_size > 100 * 1024 * 1024) {
        SetResult("max_read_buffer_size must be between 1 and 100MB");
        return TCL_ERROR;
    }

    Tcl_Obj *backlogPtr;
    Tcl_Obj *backlogKeyPtr = Tcl_NewStringObj("backlog", -1);
    Tcl_IncrRefCount(backlogKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, backlogKeyPtr, &backlogPtr)) {
        Tcl_DecrRefCount(backlogKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(backlogKeyPtr);
    if (backlogPtr) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, backlogPtr, &server_ctx->backlog)) {
            SetResult("backlog must be an integer");
            return TCL_ERROR;
        }
    }

    // check that backlog is a value between 1 and SOMAXCONN
    if (server_ctx->backlog < 1 || server_ctx->backlog > SOMAXCONN) {
        SetResult("backlog must be between 1 and SOMAXCONN");
        return TCL_ERROR;
    }

    Tcl_Obj *connTimeoutMillisPtr;
    Tcl_Obj *connTimeoutMillisKeyPtr = Tcl_NewStringObj("conn_timeout_millis", -1);
    Tcl_IncrRefCount(connTimeoutMillisKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, connTimeoutMillisKeyPtr, &connTimeoutMillisPtr)) {
        Tcl_DecrRefCount(connTimeoutMillisKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(connTimeoutMillisKeyPtr);
    if (connTimeoutMillisPtr) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, connTimeoutMillisPtr, &server_ctx->conn_timeout_millis)) {
            SetResult("max_conn_lifetime_millis must be an integer");
            return TCL_ERROR;
        }
    }

    // check that max_conn_lifetime_millis is between 1 and 1 hour
    if (server_ctx->conn_timeout_millis < 1 || server_ctx->conn_timeout_millis > 60 * 60 * 1000) {
        SetResult("conn_timeout_millis must be between 1 millisecond and 1 hour");
        return TCL_ERROR;
    }

    Tcl_Obj *garbageCollectionIntervalMillisPtr;
    Tcl_Obj *garbageCollectionIntervalMillisKeyPtr = Tcl_NewStringObj("garbage_collection_interval_millis", -1);
    Tcl_IncrRefCount(garbageCollectionIntervalMillisKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, garbageCollectionIntervalMillisKeyPtr,
                                 &garbageCollectionIntervalMillisPtr)) {
        Tcl_DecrRefCount(garbageCollectionIntervalMillisKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(garbageCollectionIntervalMillisKeyPtr);
    if (garbageCollectionIntervalMillisPtr) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, garbageCollectionIntervalMillisPtr,
                                        &server_ctx->garbage_collection_interval_millis)) {
            SetResult("garbage_collection_interval_millis must be an integer");
            return TCL_ERROR;
        }
    }

    // check that garbage_collection_interval_millis is between 1 and 1 hour
    if (server_ctx->garbage_collection_interval_millis < 1 ||
        server_ctx->garbage_collection_interval_millis > 60 * 60 * 1000) {
        SetResult("garbage_collection_interval_millis must be between 1 millisecond and 1 hour");
        return TCL_ERROR;
    }

    // read keepalive flag
    Tcl_Obj *keepalivePtr;
    Tcl_Obj *keepaliveKeyPtr = Tcl_NewStringObj("keepalive", -1);
    Tcl_IncrRefCount(keepaliveKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, keepaliveKeyPtr,
                                 &keepalivePtr)) {
        Tcl_DecrRefCount(keepaliveKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(keepaliveKeyPtr);
    if (keepalivePtr) {
        if (TCL_OK != Tcl_GetBooleanFromObj(interp, keepalivePtr, &server_ctx->keepalive)) {
            SetResult("keepalive must be a boolean");
            return TCL_ERROR;
        }
    }

    // read "keepidle" int option
    Tcl_Obj *keepidlePtr;
    Tcl_Obj *keepidleKeyPtr = Tcl_NewStringObj("keepidle", -1);
    Tcl_IncrRefCount(keepidleKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, keepidleKeyPtr, &keepidlePtr)) {
        Tcl_DecrRefCount(keepidleKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(keepidleKeyPtr);
    if (keepidlePtr) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, keepidlePtr, &server_ctx->keepidle)) {
            SetResult("keepidle must be an integer");
            return TCL_ERROR;
        }
    }

    // read "keepintvl" int option
    Tcl_Obj *keepintvlPtr;
    Tcl_Obj *keepintvlKeyPtr = Tcl_NewStringObj("keepintvl", -1);
    Tcl_IncrRefCount(keepintvlKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, keepintvlKeyPtr, &keepintvlPtr)) {
        Tcl_DecrRefCount(keepintvlKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(keepintvlKeyPtr);
    if (keepintvlPtr) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, keepintvlPtr, &server_ctx->keepintvl)) {
            SetResult("keepintvl must be an integer");
            return TCL_ERROR;
        }
    }

    // read "keepcnt" int option
    Tcl_Obj *keepcntPtr;
    Tcl_Obj *keepcntKeyPtr = Tcl_NewStringObj("keepcnt", -1);
    Tcl_IncrRefCount(keepcntKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, keepcntKeyPtr, &keepcntPtr)) {
        Tcl_DecrRefCount(keepcntKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(keepcntKeyPtr);
    if (keepcntPtr) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, keepcntPtr, &server_ctx->keepcnt)) {
            SetResult("keepcnt must be an integer");
            return TCL_ERROR;
        }
    }

    // read "gzip" boolean option
    Tcl_Obj *gzipPtr;
    Tcl_Obj *gzipKeyPtr = Tcl_NewStringObj("gzip", -1);
    Tcl_IncrRefCount(gzipKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, gzipKeyPtr, &gzipPtr)) {
        Tcl_DecrRefCount(gzipKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(gzipKeyPtr);
    if (gzipPtr) {
        if (TCL_OK != Tcl_GetBooleanFromObj(interp, gzipPtr, &server_ctx->gzip)) {
            SetResult("gzip must be a boolean");
            return TCL_ERROR;
        }
    }

    // read "gzip_min_length" int option
    Tcl_Obj *gzipMinLengthPtr;
    Tcl_Obj *gzipMinLengthKeyPtr = Tcl_NewStringObj("gzip_min_length", -1);
    Tcl_IncrRefCount(gzipMinLengthKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, gzipMinLengthKeyPtr, &gzipMinLengthPtr)) {
        Tcl_DecrRefCount(gzipMinLengthKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(gzipMinLengthKeyPtr);
    if (gzipMinLengthPtr) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, gzipMinLengthPtr, &server_ctx->gzip_min_length)) {
            SetResult("gzip_min_length must be an integer");
            return TCL_ERROR;
        }
    }
    // check that "gzip_min_length" is a positive integer
    if (server_ctx->gzip_min_length < 0) {
        SetResult("gzip_min_length must be a positive integer");
        return TCL_ERROR;
    }

    // gzip_types
    Tcl_Obj *gzipTypesPtr;
    Tcl_Obj *gzipTypesKeyPtr = Tcl_NewStringObj("gzip_types", -1);
    Tcl_IncrRefCount(gzipTypesKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, gzipTypesKeyPtr, &gzipTypesPtr)) {
        Tcl_DecrRefCount(gzipTypesKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(gzipTypesKeyPtr);
    if (gzipTypesPtr) {
        int gzip_types_count;
        Tcl_Obj **gzip_types;
        if (TCL_OK != Tcl_ListObjGetElements(interp, gzipTypesPtr, &gzip_types_count,
                                             &gzip_types)) {
            SetResult("gzip_types must be a list");
            return TCL_ERROR;
        }
        for (int i = 0; i < gzip_types_count; i++) {
            char *gzip_type = Tcl_GetString(gzip_types[i]);
            Tcl_HashEntry *entryPtr;
            int newEntry;
            entryPtr = Tcl_CreateHashEntry(&server_ctx->gzip_types_HT, gzip_type, &newEntry);
            if (newEntry) {
                Tcl_SetHashValue(entryPtr, (ClientData) NULL);
            }
            DBG(fprintf(stderr, "gzip_types: %s\n", gzip_type));
        }
    }

    Tcl_Obj *numThreadsPtr;
    Tcl_Obj *numThreadsKeyPtr = Tcl_NewStringObj("num_threads", -1);
    Tcl_IncrRefCount(numThreadsKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, numThreadsKeyPtr, &numThreadsPtr)) {
        Tcl_DecrRefCount(numThreadsKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(numThreadsKeyPtr);
    if (numThreadsPtr) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, numThreadsPtr, &server_ctx->num_threads)) {
            SetResult("num_threads must be an integer");
            return TCL_ERROR;
        }
    }
    if (server_ctx->num_threads < 0) {
        SetResult("num_threads must be >= 0");
        return TCL_ERROR;
    }
    if (server_ctx->num_threads > 0 && !server_ctx->scriptPtr) {
        SetResult("num_threads must be 0 if no thread_init_script is provided");
        return TCL_ERROR;
    }
    if (server_ctx->num_threads == 0 && server_ctx->scriptPtr != NULL) {
        SetResult("num_threads must be > 0 if a thread_init_script is provided");
        return TCL_ERROR;
    }

    Tcl_Obj *threadStacksizePtr;
    Tcl_Obj *threadStacksizeKeyPtr = Tcl_NewStringObj("thread_stacksize", -1);
    Tcl_IncrRefCount(threadStacksizeKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, threadStacksizeKeyPtr, &threadStacksizePtr)) {
        Tcl_DecrRefCount(threadStacksizeKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(threadStacksizeKeyPtr);
    if (threadStacksizePtr) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, threadStacksizePtr, &server_ctx->thread_stacksize)) {
            SetResult("thread_stacksize must be an integer");
            return TCL_ERROR;
        }
    }
    if (server_ctx->thread_stacksize < 0) {
        SetResult("thread_stacksize must be >= 0");
        return TCL_ERROR;
    }

    Tcl_Obj *threadMaxConcurrentConnsPtr;
    Tcl_Obj *threadMaxConcurrentConnsKeyPtr = Tcl_NewStringObj("thread_max_concurrent_conns", -1);
    Tcl_IncrRefCount(threadMaxConcurrentConnsKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, threadMaxConcurrentConnsKeyPtr, &threadMaxConcurrentConnsPtr)) {
        Tcl_DecrRefCount(threadMaxConcurrentConnsKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(threadMaxConcurrentConnsKeyPtr);
    if (threadMaxConcurrentConnsPtr) {
        if (TCL_OK !=
            Tcl_GetIntFromObj(interp, threadMaxConcurrentConnsPtr, &server_ctx->thread_max_concurrent_conns)) {
            SetResult("thread_max_concurrent_conns must be an integer");
            return TCL_ERROR;
        }
    }
    if (server_ctx->thread_max_concurrent_conns < 0) {
        SetResult("thread_max_concurrent_conns must be >= 0");
        return TCL_ERROR;
    }

    return TCL_OK;
}

static int tws_CreateServerCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "CreateCmd\n"));
    CheckArgs(3, 4, 1, "config_dict cmd_name ?init_script?");

    SSL_CTX *ctx;
    if (TCL_OK != create_context(interp, &ctx)) {
        return TCL_ERROR;
    }

    SSL_CTX_set_client_hello_cb(ctx, tws_ClientHelloCallback, NULL);
    tws_server_t *server_ctx = (tws_server_t *) Tcl_Alloc(sizeof(tws_server_t));
    server_ctx->sslCtx = ctx;
    server_ctx->cmdPtr = Tcl_DuplicateObj(objv[2]);
    Tcl_IncrRefCount(server_ctx->cmdPtr);
    if (objc == 4) {
        server_ctx->scriptPtr = Tcl_DuplicateObj(objv[3]);
        Tcl_IncrRefCount(server_ctx->scriptPtr);
    } else {
        server_ctx->scriptPtr = NULL;
    }
    server_ctx->accept_ctx = NULL;
    server_ctx->threadId = Tcl_GetCurrentThread();

    // configuration
    server_ctx->max_request_read_bytes = 10 * 1024 * 1024;
    server_ctx->max_read_buffer_size = 1024 * 1024;
    server_ctx->backlog = SOMAXCONN;
    server_ctx->conn_timeout_millis = 2 * 60 * 1000;  // 2 minutes
    server_ctx->garbage_collection_interval_millis = 10 * 1000;  // 10 seconds
    server_ctx->keepalive = 1;
    server_ctx->keepidle = 10;
    server_ctx->keepintvl = 5;
    server_ctx->keepcnt = 3;
    server_ctx->gzip = 1;
    server_ctx->gzip_min_length = 8192;
    Tcl_InitHashTable(&server_ctx->gzip_types_HT, TCL_STRING_KEYS);

    Tcl_HashEntry *entryPtr;
    int newEntry;
    entryPtr = Tcl_CreateHashEntry(&server_ctx->gzip_types_HT, "text/html", &newEntry);
    if (newEntry) {
        Tcl_SetHashValue(entryPtr, (ClientData) NULL);
    }

    server_ctx->num_threads = 0;
    server_ctx->thread_stacksize = TCL_THREAD_STACK_DEFAULT;
    server_ctx->thread_max_concurrent_conns = 0;

    if (TCL_OK != tws_InitServerFromConfigDict(interp, server_ctx, objv[1])) {
        Tcl_Free((char *) server_ctx);
        return TCL_ERROR;
    }

    char handle[40];
    CMD_SERVER_NAME(handle, server_ctx);
    tws_RegisterServerName(handle, server_ctx);

    SetResult(handle);
    return TCL_OK;

}

static int tws_DestroyServerCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "DestroyCmd\n"));
    CheckArgs(2, 2, 1, "handle");

    return tws_Destroy(interp, Tcl_GetString(objv[1]));

}

static int tws_ListenCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "ListenCmd\n"));
    CheckArgs(3, 3, 1, "handle port");

    return tws_Listen(interp, Tcl_GetString(objv[1]), objv[2]);

}

static int tws_AddContextCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AddContextCmd\n"));
    CheckArgs(5, 5, 1, "handle hostname key cert");

    int handle_len;
    const char *handle = Tcl_GetStringFromObj(objv[1], &handle_len);

    tws_server_t *server = tws_GetInternalFromServerName(handle);
    if (!server) {
        SetResult("server handle not found");
        return TCL_ERROR;
    }

    int hostname_len;
    const char *hostname = Tcl_GetStringFromObj(objv[2], &hostname_len);
    if (hostname_len == 0) {
        SetResult("hostname must not be empty");
        return TCL_ERROR;
    }

    int keyfile_len;
    const char *keyfile = Tcl_GetStringFromObj(objv[3], &keyfile_len);
    if (keyfile_len == 0) {
        SetResult("keyfile must not be empty");
        return TCL_ERROR;
    }

    int certfile_len;
    const char *certfile = Tcl_GetStringFromObj(objv[4], &certfile_len);
    if (certfile_len == 0) {
        SetResult("certfile must not be empty");
        return TCL_ERROR;
    }

    SSL_CTX *ctx;
    if (TCL_OK != create_context(interp, &ctx)) {
        return TCL_ERROR;
    }
    if (TCL_OK != configure_context(interp, ctx, keyfile, certfile)) {
        return TCL_ERROR;
    }
    tws_RegisterHostName(hostname, ctx);

    return TCL_OK;
}

static int tws_EncodeURIComponentCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "EncodeURIComponentCmd\n"));
    CheckArgs(2, 2, 1, "text");

    int enc_flags = CHAR_COMPONENT;

    int length;
    const char *text = Tcl_GetStringFromObj(objv[1], &length);

    Tcl_Obj *valuePtr;
    if (TCL_OK != tws_UrlEncode(interp, enc_flags, text, length, &valuePtr)) {
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, valuePtr);
    return TCL_OK;
}

static int tws_EncodeQueryCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "EncodeQueryCmd\n"));
    CheckArgs(2, 2, 1, "text");

    int enc_flags = CHAR_QUERY;

    int length;
    const char *text = Tcl_GetStringFromObj(objv[1], &length);

    Tcl_Obj *valuePtr;
    if (TCL_OK != tws_UrlEncode(interp, enc_flags, text, length, &valuePtr)) {
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, valuePtr);
    return TCL_OK;
}


static int tws_DecodeURIComponentCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "DecodeURIComponentCmd\n"));
    CheckArgs(2, 3, 1, "encoded_text ?encoding_name?");

    int length;
    const char *encoded_text = Tcl_GetStringFromObj(objv[1], &length);

    Tcl_Encoding encoding;
    if (objc == 3) {
        encoding = Tcl_GetEncoding(interp, Tcl_GetString(objv[2]));
    } else {
        encoding = Tcl_GetEncoding(interp, "utf-8");
    }

    Tcl_Obj *valuePtr = Tcl_NewStringObj("", 0);
    Tcl_IncrRefCount(valuePtr);
    if (TCL_OK != tws_UrlDecode(interp, encoding, encoded_text, length, valuePtr)) {
        Tcl_DecrRefCount(valuePtr);
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, valuePtr);
    Tcl_DecrRefCount(valuePtr);
    return TCL_OK;
}

static int tws_Base64EncodeCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "Base64EncodeCmd\n"));
    CheckArgs(2, 2, 1, "bytes");

    int input_length;
    const char *input = (const char *) Tcl_GetByteArrayFromObj(objv[1], &input_length);

    char *output = Tcl_Alloc(input_length * 2);
    size_t output_length;
    if (base64_encode(input, input_length, output, &output_length)) {
        Tcl_Free(output);
        SetResult("base64_encode failed");
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewStringObj(output, output_length));
    Tcl_Free(output);
    return TCL_OK;
}

static int tws_Base64DecodeCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "Base64DecodeCmd\n"));
    CheckArgs(2, 2, 1, "base64_encoded_string");

    int input_length;
    const char *input = Tcl_GetStringFromObj(objv[1], &input_length);

    char *output = Tcl_Alloc(3 * input_length / 4 + 2);
    size_t output_length;
    if (base64_decode(input, input_length, output, &output_length)) {
        Tcl_Free(output);
        SetResult("base64_decode failed");
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(output, output_length));
    Tcl_Free(output);
    return TCL_OK;
}

static int tws_AddHeader(Tcl_Interp *interp, Tcl_Obj *responseDictPtr, Tcl_Obj *headerNamePtr, Tcl_Obj *headerValuePtr,
                         Tcl_Obj **resultPtr) {
    Tcl_Obj *dupResponseDictPtr = Tcl_DuplicateObj(responseDictPtr);
    Tcl_IncrRefCount(dupResponseDictPtr);

    // check if the header exists in "multiValueHeaders" first
    Tcl_Obj *multiValueHeadersPtr;
    Tcl_Obj *multiValueHeadersKeyPtr = Tcl_NewStringObj("multiValueHeaders", -1);
    Tcl_IncrRefCount(multiValueHeadersKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, responseDictPtr, multiValueHeadersKeyPtr, &multiValueHeadersPtr)) {
        Tcl_DecrRefCount(multiValueHeadersKeyPtr);
        Tcl_DecrRefCount(dupResponseDictPtr);
        SetResult("add_header: error reading response dict for multiValueHeaders");
        return TCL_ERROR;
    }

    if (multiValueHeadersPtr) {
        Tcl_Obj *listValuePtr;
        if (TCL_OK != Tcl_DictObjGet(interp, multiValueHeadersPtr, headerNamePtr, &listValuePtr)) {
            Tcl_DecrRefCount(multiValueHeadersKeyPtr);
            Tcl_DecrRefCount(dupResponseDictPtr);
            SetResult("add_header: error reading multiValueHeaders for header");
            return TCL_ERROR;
        }

        if (listValuePtr) {
            if (TCL_OK != Tcl_ListObjAppendElement(interp, listValuePtr, headerValuePtr)) {
                Tcl_DecrRefCount(multiValueHeadersKeyPtr);
                Tcl_DecrRefCount(dupResponseDictPtr);
                SetResult("add_header: error appending to list of the new value of multiValueHeaders");
                return TCL_ERROR;
            }
        }

        if (TCL_OK != Tcl_DictObjPut(interp, multiValueHeadersPtr, headerNamePtr, listValuePtr)) {
            Tcl_DecrRefCount(multiValueHeadersKeyPtr);
            Tcl_DecrRefCount(dupResponseDictPtr);
            SetResult("add_header: error writing new list value to multiValueHeaders");
            return TCL_ERROR;
        }

        if (TCL_OK != Tcl_DictObjPut(interp, responseDictPtr, multiValueHeadersKeyPtr, multiValueHeadersPtr)) {
            Tcl_DecrRefCount(multiValueHeadersKeyPtr);
            Tcl_DecrRefCount(dupResponseDictPtr);
            SetResult("add_header: error writing multiValueHeaders back to response dict");
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(multiValueHeadersKeyPtr);
        Tcl_DecrRefCount(dupResponseDictPtr);
        return TCL_OK;
    }

    // check if the header exists in "headers" next, means we need to populate "multiValueHeaders"
    Tcl_Obj *headersPtr;
    Tcl_Obj *headersKeyPtr = Tcl_NewStringObj("headers", -1);
    Tcl_IncrRefCount(headersKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, responseDictPtr, headersKeyPtr, &headersPtr)) {
        Tcl_DecrRefCount(headersKeyPtr);
        Tcl_DecrRefCount(multiValueHeadersKeyPtr);
        Tcl_DecrRefCount(dupResponseDictPtr);
        SetResult("add_header: error reading headers from response dict");
        return TCL_ERROR;
    }

    if (headersPtr) {
        Tcl_Obj *valuePtr;
        if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, headerNamePtr, &valuePtr)) {
            Tcl_DecrRefCount(headersKeyPtr);
            Tcl_DecrRefCount(multiValueHeadersKeyPtr);
            Tcl_DecrRefCount(dupResponseDictPtr);
            SetResult("add_header: error reading headers from headers");
            return TCL_ERROR;
        }

        if (valuePtr) {
            // create "listValuePtr" list with the existing value and the new value
            Tcl_Obj *listValuePtr = Tcl_NewListObj(0, NULL);
            if (TCL_OK != Tcl_ListObjAppendElement(interp, listValuePtr, valuePtr)
                || TCL_OK != Tcl_ListObjAppendElement(interp, listValuePtr, headerValuePtr)) {
                Tcl_DecrRefCount(headersKeyPtr);
                Tcl_DecrRefCount(multiValueHeadersKeyPtr);
                Tcl_DecrRefCount(dupResponseDictPtr);
                SetResult("add_header: error appending to list while creating multiValueHeaders");
                return TCL_ERROR;
            }

            // create "multiValueHeaders" dict
            Tcl_Obj *newMultiValueHeadersPtr = Tcl_NewDictObj();
            if (TCL_OK != Tcl_DictObjPut(interp, newMultiValueHeadersPtr, headerNamePtr, listValuePtr)) {
                Tcl_DecrRefCount(headersKeyPtr);
                Tcl_DecrRefCount(multiValueHeadersKeyPtr);
                Tcl_DecrRefCount(dupResponseDictPtr);
                SetResult("add_header: error writing new list value to multiValueHeaders");
                return TCL_ERROR;
            }

            // write "multiValueHeaders" dict to response dict
            if (TCL_OK != Tcl_DictObjPut(interp, responseDictPtr, multiValueHeadersKeyPtr, newMultiValueHeadersPtr)) {
                Tcl_DecrRefCount(headersKeyPtr);
                Tcl_DecrRefCount(multiValueHeadersKeyPtr);
                Tcl_DecrRefCount(dupResponseDictPtr);
                SetResult("add_header: error writing multiValueHeaders back to response dict");
                return TCL_ERROR;
            }

            // we are done
        } else {
            // write to "headers" directly
            Tcl_Obj *dupHeadersPtr = Tcl_DuplicateObj(headersPtr);
            Tcl_IncrRefCount(dupHeadersPtr);
            if (TCL_OK != Tcl_DictObjPut(interp, dupHeadersPtr, headerNamePtr, headerValuePtr)) {
                Tcl_DecrRefCount(dupHeadersPtr);
                Tcl_DecrRefCount(headersKeyPtr);
                Tcl_DecrRefCount(multiValueHeadersKeyPtr);
                Tcl_DecrRefCount(dupResponseDictPtr);
                SetResult("add_header: error writing header directly to headers");
                return TCL_ERROR;
            }

            // write "headers" to response dict
            if (TCL_OK != Tcl_DictObjPut(interp, dupResponseDictPtr, headersKeyPtr, dupHeadersPtr)) {
                Tcl_DecrRefCount(dupHeadersPtr);
                Tcl_DecrRefCount(headersKeyPtr);
                Tcl_DecrRefCount(multiValueHeadersKeyPtr);
                Tcl_DecrRefCount(dupResponseDictPtr);
                SetResult("add_header: error writing headers back to response dict");
                return TCL_ERROR;
            }

            // we are done
        }
    } else {
        // create "headersPtr" dict
        headersPtr = Tcl_NewDictObj();
        if (TCL_OK != Tcl_DictObjPut(interp, headersPtr, headerNamePtr, headerValuePtr)) {
            Tcl_DecrRefCount(headersKeyPtr);
            Tcl_DecrRefCount(multiValueHeadersKeyPtr);
            Tcl_DecrRefCount(dupResponseDictPtr);
            SetResult("add_header: error writing value to headers");
            return TCL_ERROR;
        }

        // write "headersPtr" to response dict
        if (TCL_OK != Tcl_DictObjPut(interp, responseDictPtr, headersKeyPtr, headersPtr)) {
            Tcl_DecrRefCount(headersKeyPtr);
            Tcl_DecrRefCount(multiValueHeadersKeyPtr);
            Tcl_DecrRefCount(dupResponseDictPtr);
            SetResult("add_header: error writing headers back to response dict");
            return TCL_ERROR;
        }

        // we are done
    }

    *resultPtr = dupResponseDictPtr;
    Tcl_DecrRefCount(headersKeyPtr);
    Tcl_DecrRefCount(multiValueHeadersKeyPtr);
    return TCL_OK;
}

static int tws_ParseCookieCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "ParseCookieCmd\n"));
    CheckArgs(2, 2, 1, "cookie_header");

    int cookie_header_len;
    const char *cookie_header = Tcl_GetStringFromObj(objv[1], &cookie_header_len);

    Tcl_Obj *cookie_dict = Tcl_NewDictObj();
    Tcl_IncrRefCount(cookie_dict);

    Tcl_Encoding encoding = Tcl_GetEncoding(interp, "utf-8");

    // a "cookie_header" is a semicolon-separate list of key-value pairs of the form key=value
    // traverse the string of "cookie_header" and add each key-value pair to the cookie_dict
    const char *start = cookie_header;
    const char *end = cookie_header + cookie_header_len;
    const char *p = start;
    while (p < end) {
        // trim spaces in the beginning of the key
        while (CHARTYPE(space, *p)) {
            p++;
        }
        start = p;

        // find the next semicolon
        while (p < end && *p != ';') {
            p++;
        }

        // parse the key-value pair
        const char *q = start;
        while (q < p && *q != '=' && *q != ';') {
            q++;
        }

        // trim spaces in the left of the equal sign (end of the key)
        const char *r = q;
        while (r > start && CHARTYPE(space, *(r - 1))) {
            r--;
        }

        // trim spaces in the right of the equal sign (beginning of value)
        const char *s = q;
        while (s < p && CHARTYPE(space, *(s + 1))) {
            s++;
        }

        // trim spaces in the right of the value
        const char *t = p;
        while (t > s && CHARTYPE(space, *(t - 1))) {
            t--;
        }

        // add the key-value pair to the cookie_dict
        Tcl_Obj *keyPtr = Tcl_NewStringObj(start, r - start);
        Tcl_IncrRefCount(keyPtr);

        Tcl_Obj *valuePtr = Tcl_NewStringObj("", 0);
        Tcl_IncrRefCount(valuePtr);
        if (s != t) {
            if (TCL_OK != tws_UrlDecode(interp, encoding, s + 1, t - s - 1, valuePtr)) {
                Tcl_DecrRefCount(keyPtr);
                Tcl_DecrRefCount(valuePtr);
                Tcl_DecrRefCount(cookie_dict);
                return TCL_ERROR;
            }
        }

        if (TCL_OK != Tcl_DictObjPut(interp, cookie_dict, keyPtr, valuePtr)) {
            Tcl_DecrRefCount(keyPtr);
            Tcl_DecrRefCount(valuePtr);
            Tcl_DecrRefCount(cookie_dict);
            SetResult("error adding key-value pair to cookie_dict");
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(keyPtr);
        Tcl_DecrRefCount(valuePtr);

        // skip the semicolon and spaces
        while (p < end && (*p == ';' || *p == ' ')) {
            p++;
        }
        start = p;
    }

    Tcl_SetObjResult(interp, cookie_dict);
    Tcl_DecrRefCount(cookie_dict);
    return TCL_OK;

}

static int tws_AddHeaderCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AddHeaderCmd\n"));
    CheckArgs(4, 4, 1, "response_dict header_name header_value");

    Tcl_Obj *responseDictPtr;
    if (TCL_OK != tws_AddHeader(interp, objv[1], objv[2], objv[3], &responseDictPtr)) {
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, responseDictPtr);
    Tcl_DecrRefCount(responseDictPtr);
    return TCL_OK;
}

static int tws_AddCookieCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AddCookieCmd\n"));

    const char *option_path = NULL;
    const char *option_domain = NULL;
    const char *option_samesite = NULL;
    int option_maxage = -1;
    int option_httponly = 0;
    int option_partitioned = 0;
    Tcl_ArgvInfo ArgTable[] = {
            {TCL_ARGV_STRING,   "-path",        NULL,       &option_path,        "value for the Path attribute"},
            {TCL_ARGV_STRING,   "-domain",      NULL,       &option_domain,      "value for the Domain attribute"},
            {TCL_ARGV_STRING,   "-samesite",    NULL,       &option_samesite,    "value for the SameSite attribute"},
            {TCL_ARGV_INT,      "-maxage",      NULL,       &option_maxage,      "number of seconds until the cookie expires"},
            {TCL_ARGV_CONSTANT, "-httponly",    INT2PTR(1), &option_httponly,    "HttpOnly attribute is set"},
            {TCL_ARGV_CONSTANT, "-partitioned", INT2PTR(1), &option_partitioned, "indicates that the cookie should be stored using partitioned storage"},
            {TCL_ARGV_END, NULL,                NULL, NULL, NULL}
    };

    Tcl_Obj **remObjv;
    Tcl_ParseArgsObjv(interp, ArgTable, &objc, objv, &remObjv);

    if ((objc < 4) || (objc > 4)) {
        Tcl_WrongNumArgs(interp, 1, remObjv, "response_dict cookie_name cookie_value");
        return TCL_ERROR;
    }

    Tcl_Obj *headerNamePtr = Tcl_NewStringObj("Set-Cookie", 10);
    Tcl_IncrRefCount(headerNamePtr);
    Tcl_Obj *headerValuePtr = Tcl_NewStringObj("", 0);
    Tcl_IncrRefCount(headerValuePtr);

    // append cookie name and value to headerValuePtr
    Tcl_AppendObjToObj(headerValuePtr, remObjv[2]);
    Tcl_AppendToObj(headerValuePtr, "=", 1);

    // encode the cookie value
    int enc_flags = CHAR_COMPONENT;
    Tcl_Obj *cookieValuePtr;
    int cookie_value_length;
    const char *cookie_value = Tcl_GetStringFromObj(remObjv[3], &cookie_value_length);
    if (TCL_OK != tws_UrlEncode(interp, enc_flags, cookie_value, cookie_value_length, &cookieValuePtr)) {
        return TCL_ERROR;
    }
    Tcl_AppendObjToObj(headerValuePtr, cookieValuePtr);

    // append Domain
    if (option_domain) {
        Tcl_AppendToObj(headerValuePtr, "; Domain=", 9);
        Tcl_AppendToObj(headerValuePtr, option_domain, -1);
    }

    // append Path
    if (option_path) {
        Tcl_AppendToObj(headerValuePtr, "; Path=", 7);
        Tcl_AppendToObj(headerValuePtr, option_path, -1);
    } else {
        Tcl_AppendToObj(headerValuePtr, "; Path=/", 8);
    }

    // append SameSite
    if (option_samesite) {
        Tcl_AppendToObj(headerValuePtr, "; SameSite=", 11);
        Tcl_AppendToObj(headerValuePtr, option_samesite, -1);
    }

    // append Secure
    Tcl_AppendToObj(headerValuePtr, "; Secure", 8);

    // append HttpOnly
    if (option_httponly) {
        Tcl_AppendToObj(headerValuePtr, "; HttpOnly", 10);
    }

    // append Partitioned
    if (option_partitioned) {
        Tcl_AppendToObj(headerValuePtr, "; Partitioned", 12);
    }

    // append Max-Age
    if (option_maxage >= 0) {
        Tcl_AppendToObj(headerValuePtr, "; Max-Age=", 10);
        Tcl_Obj *option_maxage_ptr = Tcl_NewIntObj(option_maxage);
        Tcl_IncrRefCount(option_maxage_ptr);
        Tcl_AppendObjToObj(headerValuePtr, option_maxage_ptr);
        Tcl_DecrRefCount(option_maxage_ptr);
    }

    Tcl_Obj *responseDictPtr;
    if (TCL_OK != tws_AddHeader(interp, remObjv[1], headerNamePtr, headerValuePtr, &responseDictPtr)) {
        Tcl_DecrRefCount(headerValuePtr);
        Tcl_DecrRefCount(headerNamePtr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(headerValuePtr);
    Tcl_DecrRefCount(headerNamePtr);

    Tcl_SetObjResult(interp, responseDictPtr);
    Tcl_DecrRefCount(responseDictPtr);
    return TCL_OK;
}

static void tws_ExitHandler(ClientData unused) {
    tws_DeleteServerNameHT();
    tws_DeleteConnNameHT();
    tws_DeleteHostNameHT();
    tws_DeleteRouterNameHT();
}

void tws_InitModule() {
    if (!tws_ModuleInitialized) {
        sigset_t sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGPIPE);
        if (pthread_sigmask(SIG_BLOCK, &sigset, NULL)) {
            fprintf(stderr, "pthread_sigmask failed\n");
        }

        tws_InitServerNameHT();
        tws_InitConnNameHT();
        tws_InitHostNameHT();
        tws_InitRouterNameHT();

        Tcl_CreateThreadExitHandler(tws_ExitHandler, NULL);
        tws_ModuleInitialized = 1;
    }
}

int Twebserver_Init(Tcl_Interp *interp) {
    if (Tcl_InitStubs(interp, "8.6", 0) == NULL) {
        return TCL_ERROR;
    }

    tws_InitModule();

    Tcl_CreateNamespace(interp, "::twebserver", NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::create_server", tws_CreateServerCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::destroy_server", tws_DestroyServerCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::listen_server", tws_ListenCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::add_context", tws_AddContextCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::read_conn", tws_ReadConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::write_conn", tws_WriteConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::return_conn", tws_ReturnConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::close_conn", tws_CloseConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::keepalive_conn", tws_KeepaliveConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::info_conn", tws_InfoConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::parse_request", tws_ParseRequestCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::parse_conn", tws_ParseConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::encode_uri_component", tws_EncodeURIComponentCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::decode_uri_component", tws_DecodeURIComponentCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::encode_query", tws_EncodeQueryCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::base64_encode", tws_Base64EncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::base64_decode", tws_Base64DecodeCmd, NULL, NULL);

    Tcl_CreateObjCommand(interp, "::twebserver::create_router", tws_CreateRouterCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::add_route", tws_AddRouteCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::info_routes", tws_InfoRoutesCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::add_middleware", tws_AddMiddlewareCmd, NULL, NULL);

    Tcl_CreateObjCommand(interp, "::twebserver::parse_cookie", tws_ParseCookieCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::add_header", tws_AddHeaderCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::add_cookie", tws_AddCookieCmd, NULL, NULL);

    Tcl_CreateObjCommand(interp, "::twebserver::random_bytes", tws_RandomBytesCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::sha256", tws_Sha256Cmd, NULL, NULL);

    return Tcl_PkgProvide(interp, "twebserver", XSTR(VERSION));
}
