/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include "library.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define XSTR(s) STR(s)
#define STR(s) #s

#ifdef DEBUG
# define DBG(x) x
#else
# define DBG(x)
#endif

#define CheckArgs(min, max, n, msg) \
                 if ((objc < min) || (objc >max)) { \
                     Tcl_WrongNumArgs(interp, n, objv, msg); \
                     return TCL_ERROR; \
                 }

#define CMD_SERVER_NAME(s, internal) sprintf((s), "_TWS_SERVER_%p", (internal))
#define CMD_CONN_NAME(s, internal) sprintf((s), "_TWS_CONN_%p", (internal))
#define CHARTYPE(what, c) (is ## what ((int)((unsigned char)(c))))

static int tws_ModuleInitialized;

static Tcl_HashTable tws_ServerNameToInternal_HT;
static Tcl_Mutex tws_ServerNameToInternal_HT_Mutex;

static Tcl_HashTable tws_ConnNameToInternal_HT;
static Tcl_Mutex tws_ConnNameToInternal_HT_Mutex;

static Tcl_HashTable tws_HostNameToInternal_HT;
static Tcl_Mutex tws_HostNameToInternal_HT_Mutex;

static int tws_ModuleInitialized;

typedef struct {
    SSL_CTX *sslCtx;
    Tcl_Obj *cmdPtr;
    int max_request_read_bytes;
    int max_read_buffer_size;
} tws_server_t;

typedef struct {
    tws_server_t *server;
    SSL *ssl;
    int client;
} tws_conn_t;

static int
tws_RegisterServerName(const char *name, tws_server_t *internal) {

    Tcl_HashEntry *entryPtr;
    int newEntry;
    Tcl_MutexLock(&tws_ServerNameToInternal_HT_Mutex);
    entryPtr = Tcl_CreateHashEntry(&tws_ServerNameToInternal_HT, (char *) name, &newEntry);
    if (newEntry) {
        Tcl_SetHashValue(entryPtr, (ClientData) internal);
    }
    Tcl_MutexUnlock(&tws_ServerNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> RegisterServerName: name=%s internal=%p %s\n", name, internal,
                newEntry ? "entered into" : "already in"));

    return newEntry;
}

static int
tws_UnregisterServerName(const char *name) {

    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_ServerNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_ServerNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        Tcl_DeleteHashEntry(entryPtr);
    }
    Tcl_MutexUnlock(&tws_ServerNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> UnregisterServerName: name=%s entryPtr=%p\n", name, entryPtr));

    return entryPtr != NULL;
}

static tws_server_t *
tws_GetInternalFromServerName(const char *name) {
    tws_server_t *internal = NULL;
    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_ServerNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_ServerNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        internal = (tws_server_t *) Tcl_GetHashValue(entryPtr);
    }
    Tcl_MutexUnlock(&tws_ServerNameToInternal_HT_Mutex);

    return internal;
}

static int
tws_RegisterConnName(const char *name, tws_conn_t *internal) {

    Tcl_HashEntry *entryPtr;
    int newEntry;
    Tcl_MutexLock(&tws_ConnNameToInternal_HT_Mutex);
    entryPtr = Tcl_CreateHashEntry(&tws_ConnNameToInternal_HT, (char *) name, &newEntry);
    if (newEntry) {
        Tcl_SetHashValue(entryPtr, (ClientData) internal);
    }
    Tcl_MutexUnlock(&tws_ConnNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> RegisterConnName: name=%s internal=%p %s\n", name, internal,
                newEntry ? "entered into" : "already in"));

    return newEntry;
}

static int
tws_UnregisterConnName(const char *name) {

    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_ConnNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_ConnNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        Tcl_DeleteHashEntry(entryPtr);
    }
    Tcl_MutexUnlock(&tws_ConnNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> UnregisterConnName: name=%s entryPtr=%p\n", name, entryPtr));

    return entryPtr != NULL;
}

static tws_conn_t *
tws_GetInternalFromConnName(const char *name) {
    tws_conn_t *internal = NULL;
    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_ConnNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_ConnNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        internal = (tws_conn_t *) Tcl_GetHashValue(entryPtr);
    }
    Tcl_MutexUnlock(&tws_ConnNameToInternal_HT_Mutex);

    return internal;
}

static int
tws_RegisterHostName(const char *name, SSL_CTX *internal) {

    Tcl_HashEntry *entryPtr;
    int newEntry;
    Tcl_MutexLock(&tws_HostNameToInternal_HT_Mutex);
    entryPtr = Tcl_CreateHashEntry(&tws_HostNameToInternal_HT, (char *) name, &newEntry);
    if (newEntry) {
        Tcl_SetHashValue(entryPtr, (ClientData) internal);
    }
    Tcl_MutexUnlock(&tws_HostNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> RegisterHostName: name=%s internal=%p %s\n", name, internal,
                newEntry ? "entered into" : "already in"));

    return newEntry;
}

static int
tws_UnregisterHostName(const char *name) {

    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_HostNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_HostNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        Tcl_DeleteHashEntry(entryPtr);
    }
    Tcl_MutexUnlock(&tws_HostNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> UnregisterHostName: name=%s entryPtr=%p\n", name, entryPtr));

    return entryPtr != NULL;
}

static SSL_CTX *
tws_GetInternalFromHostName(const char *name) {
    SSL_CTX *internal = NULL;
    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_HostNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_HostNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        internal = (SSL_CTX *) Tcl_GetHashValue(entryPtr);
    }
    Tcl_MutexUnlock(&tws_HostNameToInternal_HT_Mutex);

    return internal;
}


int tws_Destroy(Tcl_Interp *interp, const char *handle) {
    tws_server_t *server = tws_GetInternalFromServerName(handle);
    if (!tws_UnregisterServerName(handle)) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("handle not found", -1));
        return TCL_ERROR;
    }

    Tcl_DecrRefCount(server->cmdPtr);
    SSL_CTX_free(server->sslCtx);

    Tcl_DeleteCommand(interp, handle);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(handle, -1));
    return TCL_OK;
}

int create_socket(int port) {
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

tws_conn_t *tws_NewConn(tws_server_t *server, int client) {
    SSL *ssl = SSL_new(server->sslCtx);
    if (ssl == NULL) {
        return NULL;
    }
    SSL_set_fd(ssl, client);
    SSL_set_accept_state(ssl);
    tws_conn_t *conn = (tws_conn_t *) Tcl_Alloc(sizeof(tws_conn_t));
    conn->server = server;
    conn->ssl = ssl;
    conn->client = client;
    return conn;
}

int tws_CloseConn(Tcl_Interp *interp, const char *conn_handle) {
    tws_conn_t *conn = tws_GetInternalFromConnName(conn_handle);
    if (!conn) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("handle not found", -1));
        return TCL_ERROR;
    }

    tws_UnregisterConnName(conn_handle);
    SSL_shutdown(conn->ssl);
    SSL_free(conn->ssl);
    shutdown(conn->client, SHUT_RDWR);
    close(conn->client);
    Tcl_Free((char *) conn);
    return TCL_OK;
}

int tws_Listen(Tcl_Interp *interp, const char *handle, Tcl_Obj *portPtr) {
    tws_server_t *server = tws_GetInternalFromServerName(handle);
    if (!server) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("handle not found", -1));
        return TCL_ERROR;
    }

    int port;
    if (Tcl_GetIntFromObj(interp, portPtr, &port) != TCL_OK) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("port must be an integer", -1));
        return TCL_ERROR;
    }

    int sock = create_socket(port);

    /* Handle connections */
    while (1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);

        int client = accept(sock, (struct sockaddr *) &addr, &len);
        if (client < 0) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("Unable to accept", -1));
            return TCL_ERROR;
        }

        tws_conn_t *conn = tws_NewConn(server, client);
        if (conn == NULL) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("Unable to create SSL connection", -1));
            return TCL_ERROR;
        }

        char conn_handle[80];
        CMD_CONN_NAME(conn_handle, conn);
        tws_RegisterConnName(conn_handle, conn);

        if (SSL_accept(conn->ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            Tcl_ResetResult(interp);
            Tcl_Obj *connPtr = Tcl_NewStringObj(conn_handle, -1);
            Tcl_Obj *addrPtr = Tcl_NewStringObj(inet_ntoa(addr.sin_addr), -1);
            Tcl_Obj *cmdobjv[] = {server->cmdPtr, connPtr, addrPtr, portPtr, NULL};
            if (TCL_OK != Tcl_EvalObjv(interp, 4, cmdobjv, TCL_EVAL_GLOBAL)) {
                tws_CloseConn(interp, conn_handle);
                DBG(fprintf(stderr, "error evaluating script sock=%d\n", sock));
                // TODO: log the error
            }
        }
    }

    return TCL_OK;
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    unsigned long op = SSL_OP_ALL;
    op |= SSL_OP_NO_SSLv2;
//    op |= SSL_OP_NO_SSLv3;
//    op |= SSL_OP_NO_TLSv1;
    SSL_CTX_set_options(ctx, op);

    return ctx;
}

void configure_context(SSL_CTX *ctx, const char *key_file, const char *cert_file) {
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// ClientHello callback
int tws_ClientHelloCallback(SSL *ssl, int *al, void *arg) {

    const unsigned char *p;
    size_t remaining;
    size_t len;
    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &p, &remaining) || remaining <= 2) {
        return SSL_CLIENT_HELLO_ERROR;
    }

    /* Extract the length of the supplied list of names. */
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 != remaining)
        return 0;
    remaining = len;
    /*
     * The list in practice only has a single element, so we only consider
     * the first one.
     */
    if (remaining == 0 || *p++ != TLSEXT_NAMETYPE_host_name)
        return 0;
    remaining--;
    /* Now we can finally pull out the byte array with the actual hostname. */
    if (remaining <= 2)
        return 0;
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 > remaining)
        return 0;
    remaining = len;
    const char *hostname = (const char *)p;

    DBG(fprintf(stderr, "hostname=%s\n", hostname));
    if (p == NULL) {
        return SSL_CLIENT_HELLO_ERROR;
    }

    SSL_CTX *ctx = tws_GetInternalFromHostName(hostname);
    if (!ctx) {
        return SSL_CLIENT_HELLO_ERROR;
    }

    SSL_set_SSL_CTX(ssl, ctx);
    return SSL_CLIENT_HELLO_SUCCESS;
}

static int tws_CreateCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "CreateCmd\n"));
    CheckArgs(3, 3, 1, "config_dict cmd_name");

    SSL_CTX *ctx = create_context();
    SSL_CTX_set_client_hello_cb(ctx, tws_ClientHelloCallback, NULL);
    tws_server_t *server_ctx = (tws_server_t *) Tcl_Alloc(sizeof(tws_server_t));
    server_ctx->sslCtx = ctx;
    server_ctx->cmdPtr = Tcl_DuplicateObj(objv[2]);
    server_ctx->max_request_read_bytes = 10 * 1024 * 1024;
    server_ctx->max_read_buffer_size = 1024 * 1024;

    Tcl_Obj *maxRequestReadBytesPtr;
    Tcl_DictObjGet(interp, objv[1], Tcl_NewStringObj("max_request_read_bytes", -1),
                   &maxRequestReadBytesPtr);
    if (maxRequestReadBytesPtr) {
        Tcl_GetIntFromObj(interp, maxRequestReadBytesPtr, &server_ctx->max_request_read_bytes);
    }

    Tcl_Obj *maxReadBufferSizePtr;
    Tcl_DictObjGet(interp, objv[1], Tcl_NewStringObj("max_read_buffer_size", -1),
                   &maxReadBufferSizePtr);
    if (maxReadBufferSizePtr) {
        Tcl_GetIntFromObj(interp, maxReadBufferSizePtr, &server_ctx->max_read_buffer_size);
    }

    char handle[80];
    CMD_SERVER_NAME(handle, server_ctx);
    tws_RegisterServerName(handle, server_ctx);

//    Tcl_CreateObjCommand(interp, handle,
//                         (Tcl_ObjCmdProc *)  tws_ClientObjCmd,
//                         NULL,
//                         NULL);

    Tcl_SetObjResult(interp, Tcl_NewStringObj(handle, -1));
    return TCL_OK;

}

static int tws_DestroyCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
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


    const char *hostname = Tcl_GetString(objv[2]);
    Tcl_Obj *keyFilePtr = objv[3];
    Tcl_Obj *certFilePtr = objv[4];
    SSL_CTX *ctx = create_context();
    configure_context(ctx, Tcl_GetString(keyFilePtr), Tcl_GetString(certFilePtr));
    tws_RegisterHostName(hostname, ctx);

    return TCL_OK;
}

static const char *ssl_errors[] = {
    "SSL_ERROR_NONE",
    "SSL_ERROR_SSL",
    "SSL_ERROR_WANT_READ",
    "SSL_ERROR_WANT_WRITE",
    "SSL_ERROR_WANT_X509_LOOKUP",
    "SSL_ERROR_SYSCALL",
    "SSL_ERROR_ZERO_RETURN",
    "SSL_ERROR_WANT_CONNECT",
    "SSL_ERROR_WANT_ACCEPT",
    "SSL_ERROR_WANT_ASYNC",
    "SSL_ERROR_WANT_ASYNC_JOB",
    "SSL_ERROR_WANT_CLIENT_HELLO_CB"
    "SSL_ERROR_WANT_RETRY_VERIFY"
};

static int tws_ReadConnCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "ReadConnCmd\n"));
    CheckArgs(2, 2, 1, "handle");

    const char *conn_handle = Tcl_GetString(objv[1]);
    tws_conn_t *conn = tws_GetInternalFromConnName(conn_handle);
    if (!conn) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("handle not found", -1));
        return TCL_ERROR;
    }

    long max_request_read_bytes = conn->server->max_request_read_bytes;
    int max_buffer_size = conn->server->max_read_buffer_size;

    char *buf = (char *) Tcl_Alloc(max_buffer_size);
    long total_read = 0;
    int rc = SSL_read(conn->ssl, buf, max_buffer_size);
    if (rc <= 0) {
        int err = SSL_get_error(conn->ssl, rc);
        tws_CloseConn(interp, conn_handle);
        Tcl_Obj *resultObjPtr = Tcl_NewStringObj("SSL_read error: ", -1);
        Tcl_AppendObjToObj(resultObjPtr, Tcl_NewStringObj(ssl_errors[err], -1));
        Tcl_SetObjResult(interp, resultObjPtr);
        Tcl_Free(buf);
        return TCL_ERROR;
    }
    int bytes_read = rc;
    Tcl_Obj *resultPtr = Tcl_NewStringObj(buf, bytes_read);
    total_read += bytes_read;
    while (SSL_pending(conn->ssl) > 0) {
        bytes_read = SSL_read(conn->ssl, buf, max_buffer_size);
        Tcl_AppendToObj(resultPtr, buf, bytes_read);
        total_read += bytes_read;
        if (total_read > max_request_read_bytes) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("request too large", -1));
            Tcl_Free(buf);
            return TCL_ERROR;
        }
    }
    Tcl_SetObjResult(interp, resultPtr);
    Tcl_Free(buf);
    return TCL_OK;
}

static int tws_WriteConnCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "WriteConnCmd\n"));
    CheckArgs(3, 3, 1, "handle text");

    const char *conn_handle = Tcl_GetString(objv[1]);
    tws_conn_t *conn = tws_GetInternalFromConnName(conn_handle);
    if (!conn) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("handle not found", -1));
        return TCL_ERROR;
    }

    int length;
    const char *reply = Tcl_GetStringFromObj(objv[2], &length);
    int rc = SSL_write(conn->ssl, reply, length);
    if (rc <= 0) {
        int err = SSL_get_error(conn->ssl, rc);
        tws_CloseConn(interp, conn_handle);
        Tcl_Obj *resultObjPtr = Tcl_NewStringObj("SSL_read error: ", -1);
        Tcl_AppendObjToObj(resultObjPtr, Tcl_NewStringObj(ssl_errors[err], -1));
        Tcl_SetObjResult(interp, resultObjPtr);
        return TCL_ERROR;
    }

    return TCL_OK;

}

static int tws_CloseConnCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "CloseConnCmd\n"));
    CheckArgs(2, 2, 1, "handle");

    const char *conn_handle = Tcl_GetString(objv[1]);
    return tws_CloseConn(interp, conn_handle);
}

// search a string for any of a set of bytes
const char *tws_strpbrk(const char *s, const char *end, const char *accept) {
    while (s < end && *s != '\0') {
        const char *p = accept;
        while (*p != '\0') {
            if (*s == *p) {
                return s;
            }
            p++;
        }
        s++;
    }
    return NULL;
}

// Bits that identify different character types. These types identify different
// bits that are set for each 8-bit character in the "shared_char_type_table".
enum shared_char_types {
    // Characters that do not require escaping in queries. Characters that do
    // not have this flag will be escaped; see url_canon_query.cc
    CHAR_QUERY = 1,
    // Valid in the username/password field.
    CHAR_USERINFO = 2,
    // Valid in a IPv4 address (digits plus dot and 'x' for hex).
    CHAR_IPV4 = 4,
    // Valid in an ASCII-representation of a hex digit (as in %-escaped).
    CHAR_HEX = 8,
    // Valid in an ASCII-representation of a decimal digit.
    CHAR_DEC = 16,
    // Valid in an ASCII-representation of an octal digit.
    CHAR_OCT = 32,
    // Characters that do not require escaping in encodeURIComponent.
    CHAR_COMPONENT = 64,
};

// This table contains the flags in "shared_char_types" for each 8-bit character.
//
// https://chromium.googlesource.com/chromium/src/+/refs/heads/main/url/url_canon_internal.cc#174
//
static const unsigned char shared_char_type_table[0x100] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x00 - 0x0f
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x10 - 0x1f
        0,                           // 0x20  ' ' (escape spaces in queries)
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x21  !
        0,                           // 0x22  "
        0,                           // 0x23  #  (invalid in query since it marks the ref)
        CHAR_QUERY | CHAR_USERINFO,  // 0x24  $
        CHAR_QUERY | CHAR_USERINFO,  // 0x25  %
        CHAR_QUERY | CHAR_USERINFO,  // 0x26  &
        0,                           // 0x27  '  (Try to prevent XSS.)
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x28  (
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x29  )
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x2a  *
        CHAR_QUERY | CHAR_USERINFO,  // 0x2b  +
        CHAR_QUERY | CHAR_USERINFO,  // 0x2c  ,
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x2d  -
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_COMPONENT,  // 0x2e  .
        CHAR_QUERY,                  // 0x2f  /
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_DEC | CHAR_OCT | CHAR_COMPONENT,  // 0x30  0
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_DEC | CHAR_OCT | CHAR_COMPONENT,  // 0x31  1
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_DEC | CHAR_OCT | CHAR_COMPONENT,  // 0x32  2
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_DEC | CHAR_OCT | CHAR_COMPONENT,  // 0x33  3
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_DEC | CHAR_OCT | CHAR_COMPONENT,  // 0x34  4
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_DEC | CHAR_OCT | CHAR_COMPONENT,  // 0x35  5
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_DEC | CHAR_OCT | CHAR_COMPONENT,  // 0x36  6
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_DEC | CHAR_OCT | CHAR_COMPONENT,  // 0x37  7
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_DEC | CHAR_COMPONENT,             // 0x38  8
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_DEC | CHAR_COMPONENT,             // 0x39  9
        CHAR_QUERY,  // 0x3a  :
        CHAR_QUERY,  // 0x3b  ;
        0,           // 0x3c  <  (Try to prevent certain types of XSS.)
        CHAR_QUERY,  // 0x3d  =
        0,           // 0x3e  >  (Try to prevent certain types of XSS.)
        CHAR_QUERY,  // 0x3f  ?
        CHAR_QUERY,  // 0x40  @
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_COMPONENT,  // 0x41  A
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_COMPONENT,  // 0x42  B
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_COMPONENT,  // 0x43  C
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_COMPONENT,  // 0x44  D
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_COMPONENT,  // 0x45  E
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_COMPONENT,  // 0x46  F
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x47  G
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x48  H
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x49  I
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x4a  J
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x4b  K
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x4c  L
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x4d  M
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x4e  N
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x4f  O
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x50  P
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x51  Q
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x52  R
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x53  S
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x54  T
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x55  U
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x56  V
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x57  W
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_COMPONENT, // 0x58  X
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x59  Y
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x5a  Z
        CHAR_QUERY,  // 0x5b  [
        CHAR_QUERY,  // 0x5c  '\'
        CHAR_QUERY,  // 0x5d  ]
        CHAR_QUERY,  // 0x5e  ^
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x5f  _
        CHAR_QUERY,  // 0x60  `
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_COMPONENT,  // 0x61  a
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_COMPONENT,  // 0x62  b
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_COMPONENT,  // 0x63  c
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_COMPONENT,  // 0x64  d
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_COMPONENT,  // 0x65  e
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_HEX | CHAR_COMPONENT,  // 0x66  f
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x67  g
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x68  h
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x69  i
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x6a  j
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x6b  k
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x6c  l
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x6d  m
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x6e  n
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x6f  o
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x70  p
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x71  q
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x72  r
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x73  s
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x74  t
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x75  u
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x76  v
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x77  w
        CHAR_QUERY | CHAR_USERINFO | CHAR_IPV4 | CHAR_COMPONENT,  // 0x78  x
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x79  y
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x7a  z
        CHAR_QUERY,  // 0x7b  {
        CHAR_QUERY,  // 0x7c  |
        CHAR_QUERY,  // 0x7d  }
        CHAR_QUERY | CHAR_USERINFO | CHAR_COMPONENT,  // 0x7e  ~
        0,           // 0x7f
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x80 - 0x8f
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x90 - 0x9f
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0xa0 - 0xaf
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0xb0 - 0xbf
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0xc0 - 0xcf
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0xd0 - 0xdf
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0xe0 - 0xef
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0xf0 - 0xff
};

static inline int tws_IsCharOfType(unsigned char c, unsigned char type) {
    return shared_char_type_table[c] & type;
}

static char hex_digits[] = "0123456789ABCDEF"; // A lookup table for hexadecimal digits

// This lookup table allows fast conversion between ASCII hex letters and their
// corresponding numerical value. The 8-bit range is divided up into 8
// regions of 0x20 characters each. Each of the three character types (numbers,
// uppercase, lowercase) falls into different regions of this range. The table
// contains the amount to subtract from characters in that range to get at
// the corresponding numerical value.
//
// https://chromium.googlesource.com/chromium/src/+/refs/heads/main/url/url_canon_internal.cc#289
//
static const char char_to_hex_lookup[8] = {
    0,         // 0x00 - 0x1f
    '0',       // 0x20 - 0x3f: digits 0 - 9 are 0x30 - 0x39
    'A' - 10,  // 0x40 - 0x5f: letters A - F are 0x41 - 0x46
    'a' - 10,  // 0x60 - 0x7f: letters a - f are 0x61 - 0x66
    0,         // 0x80 - 0x9F
    0,         // 0xA0 - 0xBF
    0,         // 0xC0 - 0xDF
    0,         // 0xE0 - 0xFF
};

static inline int tws_HexCharToValue(unsigned char c) {
  return c - char_to_hex_lookup[c / 0x20];
}

static int tws_UrlDecode(Tcl_Interp *interp, Tcl_Encoding encoding, const char *value, int value_length, Tcl_Obj **valuePtrPtr) {
    // check if url decoding is needed, value is not '\0' terminated
    const char *p = value;
    const char *end = value + value_length;
    p = tws_strpbrk(value, end, "%+");

    // no url decoding is needed
    if (p == NULL) {
        *valuePtrPtr = Tcl_NewStringObj(value, value_length);
        return TCL_OK;
    }

    // url decoding is needed
    // decode "value" into "valuePtr"

    // allocate memory for "valuePtr"
    char *valuePtr = (char *) Tcl_Alloc(value_length + 1);
    char *q = valuePtr;
    while (p != NULL) {
        // copy the part of "value" before the first "%"
        memcpy(q, value, p - value);
        q += p - value;
        value = p;
        if (*value == '%') {
            // decode "%xx" into a single char
            value++;
            if (value + 2 > end) {
                Tcl_Free(valuePtr);
                Tcl_SetObjResult(interp, Tcl_NewStringObj("urldecode error: invalid %xx sequence", -1));
                return TCL_ERROR;
            }
            if (!tws_IsCharOfType(value[0], CHAR_HEX) || !tws_IsCharOfType(value[1], CHAR_HEX)) {
                Tcl_Free(valuePtr);
                Tcl_SetObjResult(interp, Tcl_NewStringObj("urldecode error: invalid %xx sequence", -1));
                return TCL_ERROR;
            }
            unsigned char c = (tws_HexCharToValue(value[0]) << 4) + tws_HexCharToValue(value[1]);
            *q = (char) c;
            q++;
            value += 2;
        } else if (*value == '+') {
            // decode "+" into a space
            *q = ' ';
            q++;
            value++;
        }
        p = tws_strpbrk(value, end, "%+");
    }
    // copy the rest of "value" into "valuePtr"
    memcpy(q, value, end - value);
    q += end - value;

    int dstLen = 2 * (q - valuePtr) + 1;
    char *dst = (char *) Tcl_Alloc(dstLen);
    int srcRead;
    int dstWrote;
    int dstChars;
    if (TCL_OK != Tcl_ExternalToUtf(
            interp,
            encoding,
            valuePtr,
            q - valuePtr,
            TCL_ENCODING_STOPONERROR,
            NULL,
            dst,
            dstLen,
            &srcRead,
            &dstWrote,
            &dstChars)
            ) {
        Tcl_Free(dst);
        Tcl_Free(valuePtr);
        Tcl_SetObjResult(interp, Tcl_NewStringObj("urldecode error: invalid utf-8 sequence", -1));
        return TCL_ERROR;
    }
    Tcl_SetStringObj(*valuePtrPtr, dst, dstWrote);
    Tcl_Free(dst);
    Tcl_Free(valuePtr);
    return TCL_OK;
}

static int tws_UrlEncode(Tcl_Interp *interp, int enc_flags, const char *value, int value_length, Tcl_Obj **valuePtrPtr) {
    // use "enc" to encode "value" into "valuePtr"
    // allocate memory for "valuePtr"
    char *valuePtr = (char *) Tcl_Alloc(3 * value_length + 1);
    char *q = valuePtr;
    const char *p = value;
    const char *end = value + value_length;
    while (p < end) {
        unsigned char c = *p;
        if (tws_IsCharOfType(c, enc_flags)) {
            *q = c;
            q++;
        } else {
            if (c == ' ' && (enc_flags & CHAR_QUERY)) {
                // encode "c" into "+"
                *q++ = '+';
            } else {
                // encode "c" into "%xx"
                char hex0 = hex_digits[(c >> 4) & 0xF]; // Extract the high nibble of c and use it as an index in the lookup table
                char hex1 = hex_digits[c & 0xF]; // Extract the low nibble of c and use it as an index in the lookup table

                *q++ = '%';
                *q++ = hex0;
                *q++ = hex1;
            }
        }
        p++;
    }
    Tcl_SetStringObj(*valuePtrPtr, valuePtr, q - valuePtr);
    return TCL_OK;
}

static int tws_AddQueryStringParameter(Tcl_Interp *interp, Tcl_Encoding encoding, Tcl_Obj *queryStringParametersPtr,
                                       Tcl_Obj *multivalueQueryStringParametersPtr, const char *key, const char *value,
                                       int value_length) {
    // check if "key" already exists in "queryStringParameters"
    Tcl_Obj *keyPtr = Tcl_NewStringObj(key, value - key - 1);
    Tcl_Obj *valuePtr = Tcl_NewObj();
    if (TCL_OK != tws_UrlDecode(interp, encoding, value, value_length, &valuePtr)) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("query string urldecode error", -1));
        return TCL_ERROR;
    }
    Tcl_Obj *existingValuePtr;
    Tcl_DictObjGet(interp, queryStringParametersPtr, keyPtr, &existingValuePtr);
    if (existingValuePtr) {
        // check if "key" already exists in "multivalueQueryStringParameters"
        Tcl_Obj *multiValuePtr;
        Tcl_DictObjGet(interp, multivalueQueryStringParametersPtr, keyPtr, &multiValuePtr);
        if (!multiValuePtr) {
            // it does not exist, create a new list and add the existing value from queryStringParameters
            multiValuePtr = Tcl_NewListObj(0, NULL);
            Tcl_ListObjAppendElement(interp, multiValuePtr, existingValuePtr);
        }
        // append the new value to the list
        Tcl_ListObjAppendElement(interp, multiValuePtr, valuePtr);
        Tcl_DictObjPut(interp, multivalueQueryStringParametersPtr, keyPtr, multiValuePtr);
    }
    Tcl_DictObjPut(interp, queryStringParametersPtr, keyPtr, valuePtr);
    return TCL_OK;
}

static int tws_ParseQueryStringParameters(Tcl_Interp *interp, Tcl_Encoding encoding, Tcl_Obj *queryStringPtr, Tcl_Obj *resultPtr) {
    // parse "query_string" into "queryStringParameters" given that it is of the form "key1=value1&key2=value2&..."
    Tcl_Obj *queryStringParametersPtr = Tcl_NewDictObj();
    Tcl_Obj *multiValueQueryStringParametersPtr = Tcl_NewDictObj();
    int query_string_length;
    const char *query_string = Tcl_GetStringFromObj(queryStringPtr, &query_string_length);
    const char *p = query_string;
    const char *end = query_string + query_string_length;
    while (p < end) {
        const char *key = p;
        const char *value = NULL;
        while (p < end && *p != '=') {
            p++;
        }
        if (p == end) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("query string parse error", -1));
            return TCL_ERROR;
        }
        value = p + 1;
        while (p < end && *p != '&') {
            p++;
        }
        if (p == end) {
            if (TCL_OK !=
                tws_AddQueryStringParameter(interp, encoding, queryStringParametersPtr, multiValueQueryStringParametersPtr, key,
                                            value, p - value)) {
                Tcl_SetObjResult(interp, Tcl_NewStringObj("query string parse error", -1));
                return TCL_ERROR;
            }
            break;
        }
        if (TCL_OK !=
            tws_AddQueryStringParameter(interp, encoding, queryStringParametersPtr, multiValueQueryStringParametersPtr, key,
                                        value, p - value)) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("query string parse error", -1));
            return TCL_ERROR;
        }
        p++;
    }
    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("queryStringParameters", -1), queryStringParametersPtr);
    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("multiValueQueryStringParameters", -1),
                   multiValueQueryStringParametersPtr);
    return TCL_OK;
}

static int tws_ParsePathAndQueryString(Tcl_Interp *interp, Tcl_Encoding encoding, const char *url, int url_length, Tcl_Obj *resultPtr) {
    // parse "path" and "queryStringParameters" from "url"
    const char *p2 = url;
    while (p2 < url + url_length && *p2 != '\0') {
        if (*p2 == '?') {
            int path_length = p2 - url;
            Tcl_Obj *pathPtr = Tcl_NewObj();
            if (TCL_OK != tws_UrlDecode(interp, encoding, url, path_length, &pathPtr)) {
                Tcl_SetObjResult(interp, Tcl_NewStringObj("path urldecode error", -1));
                return TCL_ERROR;
            }
            Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("path", -1), pathPtr);
            int query_string_length = url + url_length - p2 - 1;
            Tcl_Obj *queryStringPtr = Tcl_NewStringObj(p2 + 1, query_string_length);
            Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("queryString", -1), queryStringPtr);
            tws_ParseQueryStringParameters(interp, encoding, queryStringPtr, resultPtr);
            break;
        }
        p2++;
    }
    if (p2 == url) {
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("path", -1), Tcl_NewStringObj(url, url_length));
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("queryString", -1), Tcl_NewStringObj("", 0));
    }
    return TCL_OK;
}

static int tws_ParseRequestLine(Tcl_Interp *interp, Tcl_Encoding encoding, const char **currPtr, const char *end, Tcl_Obj *resultPtr) {
    const char *curr = *currPtr;
    // skip spaces
    while (curr < end && CHARTYPE(space, *curr) != 0) {
        curr++;
    }
    const char *p = curr;

    // collect non-space chars as first token
    while (curr < end && CHARTYPE(space, *curr) == 0) {
        curr++;
    }
    if (curr == end) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("request line parse error: no http method", -1));
        return TCL_ERROR;
    }

    // mark the end of the token and remember as "http_method"
    curr++;
//    char *http_method = strndup(p, curr - p);
//    http_method[curr - p - 1] = '\0';
    int http_method_length = curr - p - 1;

    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("httpMethod", -1), Tcl_NewStringObj(p, http_method_length));

    // skip spaces
    while (curr < end && CHARTYPE(space, *curr) != 0) {
        curr++;
    }
    p = curr;

    // collect non-space chars as second token
    while (curr < end && CHARTYPE(space, *curr) == 0) {
        curr++;
    }
    if (curr == end) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("request line parse error: no url", -1));
        return TCL_ERROR;
    }

    // mark the end of the token and remember as "path"
    curr++;
//    char *url = strndup(p, curr - p);
//    url[curr - p - 1] = '\0';
    int url_length = curr - p - 1;

    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("url", -1), Tcl_NewStringObj(p, url_length));

    if (TCL_OK != tws_ParsePathAndQueryString(interp, encoding, p, url_length, resultPtr)) {
        return TCL_ERROR;
    }

    // skip spaces until end of line denoted by "\r\n" or "\n"
    while (curr < end && CHARTYPE(space, *curr) != 0 && *curr != '\r' && *curr != '\n') {
        curr++;
    }
    p = curr;

    if (curr == end) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("request line parse error: no version", -1));
        return TCL_ERROR;
    }

    // parse "version" if we have NOT reached the end of line
    if (*curr != '\r' && *curr != '\n') {

        // collect non-space chars as third token
        while (curr < end && CHARTYPE(space, *curr) == 0) {
            curr++;
        }
        if (curr == end) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("request line parse error: while extracting version", -1));
            return TCL_ERROR;
        }

        // mark the end of the token and remember as "version"
        curr++;
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("version", -1), Tcl_NewStringObj(p, curr - p - 1));
    }

    // skip newline chars
    while (curr < end && (*curr == '\r' || *curr == '\n')) {
        curr++;
    }
    *currPtr = curr;
    return TCL_OK;

}

static int tws_AddHeader(Tcl_Interp *interp, Tcl_Obj *headersPtr, Tcl_Obj *multiValueHeadersPtr, Tcl_Obj *keyPtr,
                         Tcl_Obj *valuePtr) {
    Tcl_Obj *existingValuePtr;
    Tcl_DictObjGet(interp, headersPtr, keyPtr, &existingValuePtr);
    if (existingValuePtr) {
        // check if "key" already exists in "multiValueHeaders"
        Tcl_Obj *multiValuePtr;
        Tcl_DictObjGet(interp, multiValueHeadersPtr, keyPtr, &multiValuePtr);
        if (!multiValuePtr) {
            // it does not exist, create a new list and add the existing value from headers
            multiValuePtr = Tcl_NewListObj(0, NULL);
            Tcl_ListObjAppendElement(interp, multiValuePtr, existingValuePtr);
        }
        // append the new value to the list
        Tcl_ListObjAppendElement(interp, multiValuePtr, valuePtr);
        Tcl_DictObjPut(interp, multiValueHeadersPtr, keyPtr, multiValuePtr);
    }
    Tcl_DictObjPut(interp, headersPtr, keyPtr, valuePtr);
    return TCL_OK;
}

static int tws_ParseHeaders(Tcl_Interp *interp, const char **currPtr, const char *end, Tcl_Obj *headersPtr,
                            Tcl_Obj *multiValueHeadersPtr) {
    // parse the headers, each header is a line of the form "key: value"
    // stop when we reach an empty line denoted by "\r\n" or "\n"
    const char *curr = *currPtr;
    while (curr < end) {
        const char *p = curr;

        // collect non-space chars as header key
        while (curr < end && CHARTYPE(space, *curr) == 0 && *curr != ':') {
            curr++;
        }
        if (curr == end) {
            goto done;
        }

        // mark the end of the token and remember as "key"
        curr++;
        int keylen = curr - p - 1;
        char *key = strndup(p, curr - p);
        // lowercase "key"
        for (int i = 0; i < keylen; i++) {
            key[i] = tolower(key[i]);
        }
        key[curr - p - 1] = '\0';
        Tcl_Obj *keyPtr = Tcl_NewStringObj(key, keylen);

        // skip spaces
        while (curr < end && CHARTYPE(space, *curr) != 0) {
            curr++;
        }
        p = curr;

        // collect all chars to the end of line as header value
        while (curr < end && *curr != '\r' && *curr != '\n') {
            curr++;
        }

        // mark the end of the token and remember as "value"
        curr++;
        int valuelen = curr - p - 1;
        char *value = strndup(p, curr - p);
        value[curr - p - 1] = '\0';
        Tcl_Obj *valuePtr = Tcl_NewStringObj(value, valuelen);

        DBG(fprintf(stderr, "key=%s value=%s\n", key, value));

        // skip spaces until end of line denoted by "\r\n" or "\n"
        while (curr < end && CHARTYPE(space, *curr) != 0 && *curr != '\r' && *curr != '\n') {
            curr++;
        }

        // check if we reached the end
        if (curr == end) {
            if (TCL_OK != tws_AddHeader(interp, headersPtr, multiValueHeadersPtr, keyPtr, valuePtr)) {
                free(key);
                free(value);
                goto done;
            }
            free(value);
            free(key);
            break;
        }

        // skip "\r\n" or "\n" at most once
        if (curr + 1 < end && *curr == '\r' && *(curr + 1) == '\n') {
            curr += 2;
        } else if (curr < end && *curr == '\r') {
            curr++;
        } else if (curr < end && *curr == '\n') {
            curr++;
        }

        // check if we reached the end
        if (curr == end) {
            if (TCL_OK != tws_AddHeader(interp, headersPtr, multiValueHeadersPtr, keyPtr, valuePtr)) {
                free(key);
                free(value);
                goto done;
            }
            free(value);
            free(key);
            break;
        }

        // check if the line starts with a space, if so, it is a continuation of the previous header
        while (curr < end && *curr == ' ') {
            fprintf(stderr, "continuation curr=%p end=%p intchar=%d\n", curr, end, (int) curr[0]);
            // skip spaces
            while (curr < end && CHARTYPE(space, *curr) != 0) {
                curr++;
            }
            p = curr;

            // read the new line to the end by advancing "curr"
            while (curr < end && *curr != '\r' && *curr != '\n') {
                curr++;
            }

            // mark the end of the string and remember as "continuation_value"
            curr++;
            int continuation_valuelen = curr - p;
            char *continuation_value = strndup(p, curr - p);
            continuation_value[curr - p - 1] = '\0';
            Tcl_Obj *continuation_valuePtr = Tcl_NewStringObj(continuation_value, continuation_valuelen);

            // append the continuation value to the previous value
            Tcl_AppendObjToObj(valuePtr, continuation_valuePtr);
            free(continuation_value);

            // skip "\r\n" or "\n" at most once
            if (curr + 1 < end && *curr == '\r' && *(curr + 1) == '\n') {
                curr += 2;
            } else if (curr < end && *curr == '\r') {
                curr++;
            } else if (curr < end && *curr == '\n') {
                curr++;
            }

        }

        if (TCL_OK != tws_AddHeader(interp, headersPtr, multiValueHeadersPtr, keyPtr, valuePtr)) {
            free(key);
            free(value);
            goto done;
        }
        free(key);
        free(value);

        // check if we reached a blank line
        if (curr + 1 < end && *curr == '\r' && *(curr + 1) == '\n') {
            curr += 2;
            break;
        } else if (curr < end && *curr == '\r') {
            curr++;
            break;
        } else if (curr < end && *curr == '\n') {
            curr++;
            break;
        }
    }
    *currPtr = curr;
    return TCL_OK;

    done:
    Tcl_SetObjResult(interp, Tcl_NewStringObj("headers parse error", -1));
    return TCL_ERROR;
}

// https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64#C
static const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_encode(const void *data_buf, size_t dataLength, char *result, size_t resultSize) {
    const uint8_t *data = (const uint8_t *) data_buf;
    size_t resultIndex = 0;
    size_t x;
    uint32_t n = 0;
    int padCount = dataLength % 3;
    uint8_t n0, n1, n2, n3;

    /* increment over the length of the string, three characters at a time */
    for (x = 0; x < dataLength; x += 3) {
        /* these three 8-bit (ASCII) characters become one 24-bit number */
        n = ((uint32_t) data[x])
                << 16; //parenthesis needed, compiler depending on flags can do the shifting before conversion to uint32_t, resulting to 0

        if ((x + 1) < dataLength)
            n += ((uint32_t) data[x + 1])
                    << 8;//parenthesis needed, compiler depending on flags can do the shifting before conversion to uint32_t, resulting to 0

        if ((x + 2) < dataLength)
            n += data[x + 2];

        /* this 24-bit number gets separated into four 6-bit numbers */
        n0 = (uint8_t) (n >> 18) & 63;
        n1 = (uint8_t) (n >> 12) & 63;
        n2 = (uint8_t) (n >> 6) & 63;
        n3 = (uint8_t) n & 63;

        /*
         * if we have one byte available, then its encoding is spread
         * out over two characters
         */
        if (resultIndex >= resultSize) return -1;   /* indicate failure: buffer too small */
        result[resultIndex++] = base64chars[n0];
        if (resultIndex >= resultSize) return -1;   /* indicate failure: buffer too small */
        result[resultIndex++] = base64chars[n1];

        /*
         * if we have only two bytes available, then their encoding is
         * spread out over three chars
         */
        if ((x + 1) < dataLength) {
            if (resultIndex >= resultSize) return -1;   /* indicate failure: buffer too small */
            result[resultIndex++] = base64chars[n2];
        }

        /*
         * if we have all three bytes available, then their encoding is spread
         * out over four characters
         */
        if ((x + 2) < dataLength) {
            if (resultIndex >= resultSize) return -1;   /* indicate failure: buffer too small */
            result[resultIndex++] = base64chars[n3];
        }
    }

    /*
     * create and add padding that is required if we did not have a multiple of 3
     * number of characters available
     */
    if (padCount > 0) {
        for (; padCount < 3; padCount++) {
            if (resultIndex >= resultSize) return -1;   /* indicate failure: buffer too small */
            result[resultIndex++] = '=';
        }
    }
    if (resultIndex >= resultSize) return -1;   /* indicate failure: buffer too small */
    result[resultIndex] = 0;
    return resultIndex;   /* indicate success */
}

static int
tws_ParseBody(Tcl_Interp *interp, const char *curr, const char *end, Tcl_Obj *resultPtr, Tcl_Obj *contentLengthPtr,
              Tcl_Obj *contentTypePtr) {
    int contentLength;
    if (contentLengthPtr) {
        if (Tcl_GetIntFromObj(interp, contentLengthPtr, &contentLength) != TCL_OK) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("Content-Length must be an integer", -1));
            return TCL_ERROR;
        }

        // check if we have enough bytes in the body
        if (end - curr < contentLength) {
            contentLength = end - curr;
        }
    } else {
        if (curr == end) {
            return TCL_OK;
        }

        contentLength = end - curr;
    }

    DBG(fprintf(stderr, "contentLength=%d\n", contentLength));

    int base64_encoded = 0;
    if (contentTypePtr) {
        int contentTypeLength;
        const char *content_type = Tcl_GetStringFromObj(contentTypePtr, &contentTypeLength);
        // check if binary mime type: image/* and application/octet
        if (contentTypeLength >= 16 && strncmp(content_type, "application/octet", 16) == 0) {
            base64_encoded = 1;
        } else if (contentTypeLength >= 6 && strncmp(content_type, "image/", 6) == 0) {
            base64_encoded = 1;
        }
    }
    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("isBase64Encoded", -1), Tcl_NewBooleanObj(base64_encoded));

    if (base64_encoded) {
        // base64 encode the body and remember as "body"
        char *body = Tcl_Alloc(contentLength * 2);
        int bodyLength = base64_encode(curr, contentLength, body, contentLength * 2);
        if (bodyLength == -1) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("base64_encode failed", -1));
            return TCL_ERROR;
        }
        Tcl_Obj *bodyPtr = Tcl_NewStringObj(body, bodyLength);
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("body", -1), bodyPtr);
        Tcl_Free(body);
    } else {
        // mark the end of the token and remember as "body"
        char *body = strndup(curr, contentLength + 1);
        body[contentLength] = '\0';
        Tcl_Obj *bodyPtr = Tcl_NewStringObj(body, contentLength);
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("body", -1), bodyPtr);
        free(body);
    }
}

static int tws_ParseRequestCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "ParseRequestCmd\n"));
    CheckArgs(2, 3, 1, "request ?encoding_name?");

    int length;
    const char *request = Tcl_GetStringFromObj(objv[1], &length);

    Tcl_Encoding encoding;
    if (objc == 3) {
        encoding = Tcl_GetEncoding(interp, Tcl_GetString(objv[2]));
    } else {
        encoding = Tcl_GetEncoding(interp, "utf-8");
    }

    DBG(fprintf(stderr, "request=%s\n", request));

//    String version;
//    String path;
//    String httpMethod;
//    Map<String, String> headers;
//    Map<String, List<String>> multiValueHeaders;
//    Map<String, String> queryStringParameters;
//    Map<String, List<String>> multiValueQueryStringParameters;
//    Map<String, String> pathParameters;
//    String body;
//    Boolean isBase64Encoded;
    Tcl_Obj *resultPtr = Tcl_NewDictObj();

    const char *curr = request;
    const char *end = request + length;

    // parse the first line of the request
    if (TCL_OK != tws_ParseRequestLine(interp, encoding, &curr, end, resultPtr)) {
        return TCL_ERROR;
    }

    Tcl_Obj *headersPtr = Tcl_NewDictObj();
    Tcl_Obj *multiValueHeadersPtr = Tcl_NewDictObj();
    if (TCL_OK != tws_ParseHeaders(interp, &curr, end, headersPtr, multiValueHeadersPtr)) {
        return TCL_ERROR;
    }
    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("headers", -1), headersPtr);
    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("multiValueHeaders", -1), multiValueHeadersPtr);

    // get "Content-Length" header
    Tcl_Obj *contentLengthPtr;
    Tcl_DictObjGet(interp, headersPtr, Tcl_NewStringObj("content-length", -1), &contentLengthPtr);
    Tcl_Obj *contentTypePtr;
    Tcl_DictObjGet(interp, headersPtr, Tcl_NewStringObj("content-type", -1), &contentTypePtr);
    tws_ParseBody(interp, curr, end, resultPtr, contentLengthPtr, contentTypePtr);

    Tcl_SetObjResult(interp, resultPtr);
    return TCL_OK;

}


static int tws_EncodeURIComponentCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "EncodeURIComponentCmd\n"));
    CheckArgs(2, 2, 1, "text");

    int enc_flags = CHAR_COMPONENT;

    int length;
    const char *text = Tcl_GetStringFromObj(objv[1], &length);

    Tcl_Obj *valuePtr = Tcl_NewObj();
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

    Tcl_Obj *valuePtr = Tcl_NewObj();
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

    Tcl_Obj *valuePtr = Tcl_NewObj();
    if (TCL_OK != tws_UrlDecode(interp, encoding, encoded_text, length, &valuePtr)) {
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, valuePtr);
    return TCL_OK;
}

static void tws_ExitHandler(ClientData unused) {
}


void tws_InitModule() {
    if (!tws_ModuleInitialized) {
        Tcl_InitHashTable(&tws_ServerNameToInternal_HT, TCL_STRING_KEYS);
        Tcl_InitHashTable(&tws_ConnNameToInternal_HT, TCL_STRING_KEYS);
        Tcl_InitHashTable(&tws_HostNameToInternal_HT, TCL_STRING_KEYS);
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
    Tcl_CreateObjCommand(interp, "::twebserver::create_server", tws_CreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::destroy_server", tws_DestroyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::listen_server", tws_ListenCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::add_context", tws_AddContextCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::read_conn", tws_ReadConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::write_conn", tws_WriteConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::close_conn", tws_CloseConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::parse_request", tws_ParseRequestCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::encode_uri_component", tws_EncodeURIComponentCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::decode_uri_component", tws_DecodeURIComponentCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::encode_query", tws_EncodeQueryCmd, NULL, NULL);

    return Tcl_PkgProvide(interp, "twebserver", XSTR(VERSION));
}
