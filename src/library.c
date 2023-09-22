/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include "library.h"
#include "base64.h"
#include "uri.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <fcntl.h>

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

#define SetResult(str) Tcl_ResetResult(interp); \
                     Tcl_SetStringObj(Tcl_GetObjResult(interp), (str), -1)

#define CMD_SERVER_NAME(s, internal) sprintf((s), "_TWS_SERVER_%p", (internal))
#define CMD_CONN_NAME(s, internal) sprintf((s), "_TWS_CONN_%p", (internal))
#define CHARTYPE(what, c) (is ## what ((int)((unsigned char)(c))))

static int tws_ModuleInitialized;

static Tcl_Mutex tws_Eval_Mutex;

static Tcl_HashTable tws_ServerNameToInternal_HT;
static Tcl_Mutex tws_ServerNameToInternal_HT_Mutex;

static Tcl_HashTable tws_ConnNameToInternal_HT;
static Tcl_Mutex tws_ConnNameToInternal_HT_Mutex;

static Tcl_HashTable tws_HostNameToInternal_HT;
static Tcl_Mutex tws_HostNameToInternal_HT_Mutex;

static int tws_ModuleInitialized;

typedef struct {
    int sock;
    int port;
    Tcl_Interp *interp;
} tws_accept_ctx_t;

typedef struct {
    SSL_CTX *sslCtx;
    Tcl_Obj *cmdPtr;
    tws_accept_ctx_t *accept_ctx;
    Tcl_ThreadId thread_id;
    int max_request_read_bytes;
    int max_read_buffer_size;
    int backlog;
    int conn_timeout_millis;
    int garbage_collection_interval_millis;
} tws_server_t;

typedef enum tws_CompressionMethod {
    NO_COMPRESSION,
    GZIP_COMPRESSION,
    BROTLI_COMPRESSION
} tws_compression_method_t;

typedef struct {
    tws_server_t *server;
    SSL *ssl;
    int client;
    long long latest_millis;
    // refactor the following into a flags field
    tws_compression_method_t compression;
    int keepalive;
    int created_file_handler_p;
    int todelete;
} tws_conn_t;

typedef struct {
    Tcl_EventProc *proc;    /* Function to call to service this event. */
    Tcl_Event *nextPtr;    /* Next in list of pending events, or NULL. */
    ClientData *clientData; // The pointer to the client data
} tws_keepalive_event_t;

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
        "SSL_ERROR_WANT_CLIENT_HELLO_CB",
        "SSL_ERROR_WANT_RETRY_VERIFY"
};

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
    if (!server) {
        SetResult("server handle not found");
        return TCL_ERROR;
    }
    if (!tws_UnregisterServerName(handle)) {
        SetResult("unregister server name failed");
        return TCL_ERROR;
    }

    if (server->accept_ctx != NULL) {
        Tcl_DeleteFileHandler(server->accept_ctx->sock);
        Tcl_Free((char *) server->accept_ctx);
    }
    Tcl_DecrRefCount(server->cmdPtr);
    SSL_CTX_free(server->sslCtx);
    Tcl_DeleteCommand(interp, handle);
    Tcl_Free((char *) server);
    return TCL_OK;
}

static int create_socket(Tcl_Interp *interp, tws_server_t *server, int port, int *sock) {
    int fd;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        SetResult("Unable to create socket");
        return TCL_ERROR;
    }

    // Set the close-on-exec flag so that the socket will not get inherited by child processes.
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    int reuseaddr = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &reuseaddr, sizeof(reuseaddr))) {
        DBG(fprintf(stderr, "setsockopt SO_REUSEADDR failed"));
    }

    int keepalive = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive))) {
        DBG(fprintf(stderr, "setsockopt SO_KEEPALIVE failed"));
    }

    // Set the TCP_KEEPIDLE option on the socket
    int idle = 10;  // The time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int)) == -1) {
        DBG(fprintf(stderr, "setsockopt TCP_KEEPIDLE failed"));
    }

    // Set the TCP_KEEPINTVL option on the socket
    int interval = 5;  // The time (in seconds) between individual keepalive probes
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int)) == -1) {
        DBG(fprintf(stderr, "setsockopt TCP_KEEPINTVL failed"));
    }

    // Set the TCP_KEEPCNT option on the socket
    int maxpkt = 3;  // The maximum number of keepalive probes TCP should send before dropping the connection
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &maxpkt, sizeof(int)) == -1) {
        DBG(fprintf(stderr, "setsockopt TCP_KEEPCNT failed"));
    }

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        SetResult("Unable to bind");
        return TCL_ERROR;
    }

    int backlog = server->backlog; // the maximum length to which the  queue  of pending  connections  for sockfd may grow
    if (listen(fd, backlog) < 0) {
        SetResult("Unable to listen");
        return TCL_ERROR;
    }

    *sock = fd;
    return TCL_OK;
}

long long current_time_in_millis() {
    // get current tv
    struct timeval tv;
    gettimeofday(&tv, NULL);
    // convert tv to milliseconds
    long long milliseconds = (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000LL);
    return milliseconds;
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
    conn->compression = NO_COMPRESSION;
    conn->keepalive = 0;
    conn->created_file_handler_p = 0;
    conn->todelete = 0;

    conn->latest_millis = current_time_in_millis();

    return conn;
}

static int tws_DeleteFileHandlerForKeepaliveConn(Tcl_Event *evPtr, int flags) {
    DBG(fprintf(stderr, "tws_DeleteFileHandlerForKeepaliveConn\n"));
    tws_keepalive_event_t *keepaliveEvPtr = (tws_keepalive_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) keepaliveEvPtr->clientData;
    Tcl_DeleteFileHandler(conn->client);
    conn->todelete = 1;
    return 1;
}

static void tws_KeepaliveConnHandler(void *data, int mask);

static void tws_ShutdownConn(tws_conn_t *conn, int force) {
    int shutdown_client = 1;
    if (SSL_is_init_finished(conn->ssl)) {
        DBG(fprintf(stderr, "SSL_is_init_finished: true\n"));
        int rc = SSL_shutdown(conn->ssl);
        DBG(fprintf(stderr, "first SSL_shutdown rc: %d\n", rc));
        if (rc == 0) {
            shutdown(conn->client, SHUT_RDWR);
            shutdown_client = 0;
            rc = SSL_shutdown(conn->ssl);
            DBG(fprintf(stderr, "second SSL_shutdown rc: %d\n", rc));
        } else if (rc < 0) {
            int sslerr = SSL_get_error(conn->ssl, rc);
            DBG(fprintf(stderr, "SSL_get_error after first SSL_shutdown: %s\n", ssl_errors[sslerr]));
        }
    }
    DBG(fprintf(stderr, "shutdown_client: %d\n", shutdown_client));
    if (shutdown_client) {
//        shutdown(conn->client, SHUT_WR);
//        shutdown(conn->client, SHUT_RD);
        if (shutdown(conn->client, SHUT_RDWR)) {
            int error;
            getsockopt(conn->client, SOL_SOCKET, SO_ERROR, &error, &(socklen_t) {sizeof(error)});
            DBG(fprintf(stderr, "failed to shutdown client: %d error=%d\n", conn->client, error));
        }
    }
    if (close(conn->client)) {
        DBG(fprintf(stderr, "close failed\n"));
    }

    if (conn->created_file_handler_p == 1) {
        DBG(fprintf(stderr, "delete file handler client: %d\n", conn->client));
//        Tcl_DeleteFileHandler(conn->client);

        // notify the event loop to delete the file handler for keepalive
        tws_keepalive_event_t *evPtr = (tws_keepalive_event_t *) Tcl_Alloc(sizeof(tws_keepalive_event_t));
        evPtr->proc = tws_DeleteFileHandlerForKeepaliveConn;
        evPtr->nextPtr = NULL;
        evPtr->clientData = (ClientData *) conn;
        Tcl_ThreadQueueEvent(conn->server->thread_id, (Tcl_Event *) evPtr, TCL_QUEUE_TAIL);
        Tcl_ThreadAlert(conn->server->thread_id);
    }

    if (!conn->keepalive) {
        SSL_free(conn->ssl);
        Tcl_Free((char *) conn);
    }
    DBG(fprintf(stderr, "done shutdown\n"));
}

static void tws_CleanupConnections(ClientData clientData) {
    tws_server_t *server = (tws_server_t *) clientData;
    DBG(fprintf(stderr, "tws_CleanupConnections\n"));

    long long milliseconds = current_time_in_millis();

    Tcl_HashEntry *entryPtr;
    Tcl_HashSearch search;
    Tcl_MutexLock(&tws_ConnNameToInternal_HT_Mutex);
    int count = 0;
    int count_mark_for_deletion = 0;
    for (entryPtr = Tcl_FirstHashEntry(&tws_ConnNameToInternal_HT, &search); entryPtr != NULL;
         entryPtr = Tcl_NextHashEntry(&search)) {
        tws_conn_t *conn = (tws_conn_t *) Tcl_GetHashValue(entryPtr);
        if (conn->todelete) {
            DBG(fprintf(stderr, "tws_CleanupConnections - deleting conn - client: %d\n", conn->client));

            SSL_free(conn->ssl);
            Tcl_Free((char *) conn);
            Tcl_DeleteHashEntry(entryPtr);

            DBG(fprintf(stderr, "tws_CleanupConnections - deleted conn - client: %d\n", conn->client));
        } else {
            long long elapsed = milliseconds - conn->latest_millis;
            if (elapsed > conn->server->conn_timeout_millis) {
                DBG(fprintf(stderr, "tws_CleanupConnections - mark connection for deletion\n"));
//                tws_ShutdownConn(conn, 2);
                shutdown(conn->client, SHUT_RDWR);
                close(conn->client);
                conn->todelete = 1;
                count_mark_for_deletion++;
            }
        }
        count++;
    }
    DBG(fprintf(stderr, "reviewed count: %d marked_for_deletion: %d\n", count, count_mark_for_deletion));
    Tcl_MutexUnlock(&tws_ConnNameToInternal_HT_Mutex);
    Tcl_CreateTimerHandler(server->garbage_collection_interval_millis, tws_CleanupConnections, clientData);
}

static int tws_CreateFileHandlerForKeepaliveConn(Tcl_Event *evPtr, int flags) {
    DBG(fprintf(stderr, "tws_CreateFileHandlerForKeepaliveConn\n"));
    tws_keepalive_event_t *keepaliveEvPtr = (tws_keepalive_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) keepaliveEvPtr->clientData;
    DBG(fprintf(stderr, "tws_CreateFileHandlerForKeepaliveConn conn=%p client=%d\n", conn, conn->client));
    conn->created_file_handler_p = 1;
    Tcl_CreateFileHandler(conn->client, TCL_READABLE, tws_KeepaliveConnHandler, conn);
    return 1;
}

int tws_CloseConn(tws_conn_t *conn, const char *conn_handle, int force) {
    DBG(fprintf(stderr, "CloseConn - client: %d force: %d keepalive: %d handler: %d\n", conn->client, force,
                conn->keepalive, conn->created_file_handler_p));
    if (force) {
        tws_ShutdownConn(conn, force);
        if (!conn->keepalive) {
            if (!tws_UnregisterConnName(conn_handle)) {
                DBG(fprintf(stderr, "already unregistered conn_handle=%s\n", conn_handle));
                return TCL_ERROR;
            }
        }
    } else {
        if (!conn->keepalive) {
            tws_ShutdownConn(conn, 2);
            if (!tws_UnregisterConnName(conn_handle)) {
                DBG(fprintf(stderr, "already unregistered conn_handle=%s\n", conn_handle));
                return TCL_ERROR;
            }
        }
    }

    return TCL_OK;
}

static void tws_HandleConn(tws_conn_t *conn, char *conn_handle) {
    tws_server_t *server = conn->server;

    ERR_clear_error();
    if (SSL_accept(conn->ssl) <= 0) {
        DBG(fprintf(stderr, "SSL_accept <= 0 client: %d\n", conn->client));
        tws_CloseConn(conn, conn_handle, 1);
        ERR_print_errors_fp(stderr);
        return;
    } else {

        char c;
        int rc = SSL_peek(conn->ssl, &c, 1);
        if (rc <= 0) {
            DBG(fprintf(stderr, "SSL_peek <= 0 client: %d sslerr: %s\n",
                        conn->client, ssl_errors[SSL_get_error(conn->ssl, rc)]));
            tws_CloseConn(conn, conn_handle, 1);
            ERR_print_errors_fp(stderr);
            return;
        }

        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        getpeername(conn->client, (struct sockaddr *) &addr, &len);

        Tcl_Obj *const connPtr = Tcl_NewStringObj(conn_handle, -1);
        Tcl_Obj *const addrPtr = Tcl_NewStringObj(inet_ntoa(addr.sin_addr), -1);
        Tcl_Obj *const portPtr = Tcl_NewIntObj(server->accept_ctx->port);
        Tcl_Obj *const cmdobjv[] = {server->cmdPtr, connPtr, addrPtr, portPtr, NULL};

        Tcl_IncrRefCount(connPtr);
        Tcl_IncrRefCount(addrPtr);
        Tcl_IncrRefCount(portPtr);

        Tcl_MutexLock(&tws_Eval_Mutex);
        Tcl_ResetResult(server->accept_ctx->interp);
        if (TCL_OK != Tcl_EvalObjv(server->accept_ctx->interp, 4, cmdobjv, TCL_EVAL_INVOKE)) {
            DBG(fprintf(stderr, "error evaluating script sock=%d\n", conn->client));
            DBG(fprintf(stderr, "error=%s\n", Tcl_GetString(Tcl_GetObjResult(server->accept_ctx->interp))));
            Tcl_MutexUnlock(&tws_Eval_Mutex);
            Tcl_DecrRefCount(connPtr);
            Tcl_DecrRefCount(addrPtr);
            Tcl_DecrRefCount(portPtr);
            return;
        }
        Tcl_MutexUnlock(&tws_Eval_Mutex);

        Tcl_DecrRefCount(connPtr);
        Tcl_DecrRefCount(addrPtr);
        Tcl_DecrRefCount(portPtr);

    }
}

static void tws_KeepaliveConnHandler(void *data, int mask) {
    DBG(fprintf(stderr, "tws_KeepaliveConnHandler mask=%d\n", mask));
    tws_conn_t *conn = (tws_conn_t *) data;

    // reuse conn
    char conn_handle[80];
    CMD_CONN_NAME(conn_handle, conn);
//    tws_RegisterConnName(conn_handle, conn);

    DBG(fprintf(stderr, "tws_KeepaliveConnHandler - keepalive client: %d %s\n", conn->client, conn_handle));

    // populate "conn->latest_millis"
    conn->latest_millis = current_time_in_millis();

    tws_HandleConn(conn, conn_handle);
}

static void tws_AcceptConn(void *data, int mask) {
    tws_server_t *server = (tws_server_t *) data;
    struct sockaddr_in addr;
    unsigned int len = sizeof(addr);

    DBG(fprintf(stderr, "-------------------tws_AcceptConn\n"));

    int client = accept(server->accept_ctx->sock, (struct sockaddr *) &addr, &len);
    DBG(fprintf(stderr, "client: %d, addr: %s\n", client, inet_ntoa(addr.sin_addr)));
    if (client < 0) {
        DBG(fprintf(stderr, "Unable to accept"));
        return;
    }

    tws_conn_t *conn = tws_NewConn(server, client);
    if (conn == NULL) {
        shutdown(client, SHUT_WR);
        shutdown(client, SHUT_RD);
        close(client);
        DBG(fprintf(stderr, "Unable to create SSL connection"));
        return;
    }

    char conn_handle[80];
    CMD_CONN_NAME(conn_handle, conn);
    tws_RegisterConnName(conn_handle, conn);

    tws_HandleConn(conn, conn_handle);
}

int tws_Listen(Tcl_Interp *interp, const char *handle, Tcl_Obj *portPtr) {

    tws_server_t *server = tws_GetInternalFromServerName(handle);
    if (!server) {
        SetResult("server handle not found");
        return TCL_ERROR;
    }

    int port;
    if (Tcl_GetIntFromObj(interp, portPtr, &port) != TCL_OK) {
        SetResult("port must be an integer");
        return TCL_ERROR;
    }

    int sock;
    if (TCL_OK != create_socket(interp, server, port, &sock)) {
        return TCL_ERROR;
    }
    if (sock < 0) {
        SetResult("Unable to create socket");
        return TCL_ERROR;
    }

    tws_accept_ctx_t *accept_ctx = (tws_accept_ctx_t *) Tcl_Alloc(sizeof(tws_accept_ctx_t));
    accept_ctx->sock = sock;
    accept_ctx->port = port;
    accept_ctx->interp = interp;
    server->accept_ctx = accept_ctx;
    Tcl_CreateFileHandler(sock, TCL_READABLE, tws_AcceptConn, server);
    Tcl_CreateTimerHandler(server->garbage_collection_interval_millis, tws_CleanupConnections, server);
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

    return TCL_OK;
}

static int tws_CreateCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "CreateCmd\n"));
    CheckArgs(3, 3, 1, "config_dict cmd_name");

    SSL_CTX *ctx;
    if (TCL_OK != create_context(interp, &ctx)) {
        return TCL_ERROR;
    }

    SSL_CTX_set_client_hello_cb(ctx, tws_ClientHelloCallback, NULL);
    tws_server_t *server_ctx = (tws_server_t *) Tcl_Alloc(sizeof(tws_server_t));
    server_ctx->sslCtx = ctx;
    server_ctx->cmdPtr = Tcl_DuplicateObj(objv[2]);
    Tcl_IncrRefCount(server_ctx->cmdPtr);
    server_ctx->max_request_read_bytes = 10 * 1024 * 1024;
    server_ctx->max_read_buffer_size = 1024 * 1024;
    server_ctx->backlog = 1024;
    server_ctx->conn_timeout_millis = 15 * 60 * 1000;  // 15 minutes
    server_ctx->garbage_collection_interval_millis = 60 * 1000;  // 60 seconds
    server_ctx->accept_ctx = NULL;
    server_ctx->thread_id = Tcl_GetCurrentThread();

    if (TCL_OK != tws_InitServerFromConfigDict(interp, server_ctx, objv[1])) {
        Tcl_Free((char *) server_ctx);
        return TCL_ERROR;
    }

    char handle[80];
    CMD_SERVER_NAME(handle, server_ctx);
    tws_RegisterServerName(handle, server_ctx);

    SetResult(handle);
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

static int tws_ReadConn(Tcl_Interp *interp, tws_conn_t *conn, const char *conn_handle, Tcl_DString *dsPtr) {
    DBG(fprintf(stderr, "ReadConn client: %d\n", conn->client));
    long max_request_read_bytes = conn->server->max_request_read_bytes;
    int max_buffer_size = conn->server->max_read_buffer_size;

    char *buf = (char *) Tcl_Alloc(max_buffer_size);
    long total_read = 0;
    int rc;
    int bytes_read;
    for (;;) {
        rc = SSL_read(conn->ssl, buf, max_buffer_size);
        if (rc > 0) {
            bytes_read = rc;
            Tcl_DStringAppend(dsPtr, buf, bytes_read);
            total_read += bytes_read;
            if (total_read > max_request_read_bytes) {
                goto failed_due_to_request_too_large;
            }
        } else {
            int err = SSL_get_error(conn->ssl, rc);
            if (err == SSL_ERROR_WANT_READ) {
                bytes_read = rc;
                Tcl_DStringAppend(dsPtr, buf, bytes_read);
                total_read += bytes_read;
                if (total_read > max_request_read_bytes) {
                    goto failed_due_to_request_too_large;
                }
                continue;
            }

            Tcl_Free(buf);
            tws_CloseConn(conn, conn_handle, 1);
            SetResult("SSL_read error");
            return TCL_ERROR;
        }
        break;
    }
    Tcl_Free(buf);
    return TCL_OK;

    failed_due_to_request_too_large:
    Tcl_Free(buf);
    tws_CloseConn(conn, conn_handle, 2);
    SetResult("request too large");
    return TCL_ERROR;

}

static int tws_ReadConnCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "ReadConnCmd\n"));
    CheckArgs(2, 2, 1, "conn_handle");

    const char *conn_handle = Tcl_GetString(objv[1]);
    tws_conn_t *conn = tws_GetInternalFromConnName(conn_handle);
    if (!conn) {
        SetResult("read_conn: conn handle not found");
        return TCL_ERROR;
    }

    Tcl_DString ds;
    Tcl_DStringInit(&ds);
    if (TCL_OK != tws_ReadConn(interp, conn, conn_handle, &ds)) {
        Tcl_DStringFree(&ds);
        return TCL_ERROR;
    }
    Tcl_DStringResult(interp, &ds);
    Tcl_DStringFree(&ds);
    return TCL_OK;
}

static int tws_WriteConnCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "WriteConnCmd\n"));
    CheckArgs(3, 3, 1, "conn_handle text");

    const char *conn_handle = Tcl_GetString(objv[1]);
    tws_conn_t *conn = tws_GetInternalFromConnName(conn_handle);
    if (!conn) {
        SetResult("write_conn: conn handle not found");
        return TCL_ERROR;
    }

    int length;
    const char *reply = Tcl_GetStringFromObj(objv[2], &length);
    int rc = SSL_write(conn->ssl, reply, length);
    if (rc <= 0) {
        int err = SSL_get_error(conn->ssl, rc);
        tws_CloseConn(conn, conn_handle, 1);
        SetResult("write_conn: SSL_write error");
        return TCL_ERROR;
    }

    return TCL_OK;

}

static int tws_ReturnConnCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "ReturnConnCmd\n"));
    CheckArgs(3, 4, 1, "conn_handle response ?encoding_name?");

    const char *conn_handle = Tcl_GetString(objv[1]);
    tws_conn_t *conn = tws_GetInternalFromConnName(conn_handle);
    if (!conn) {
        SetResult("return_conn: conn handle not found");
        return TCL_ERROR;
    }

    // "response" is a dictionary of the form:
    //    Integer statusCode;
    //    Map<String, String> headers;
    //    Map<String, List<String>> multiValueHeaders;
    //    String body;
    //    Boolean isBase64Encoded;

    Tcl_Obj *statusCodePtr;
    Tcl_Obj *statusCodeKeyPtr = Tcl_NewStringObj("statusCode", -1);
    Tcl_IncrRefCount(statusCodeKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[2], statusCodeKeyPtr, &statusCodePtr)) {
        Tcl_DecrRefCount(statusCodeKeyPtr);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(statusCodeKeyPtr);
    if (!statusCodePtr) {
        SetResult("statusCode not found");
        return TCL_ERROR;
    }
    Tcl_Obj *headersPtr;
    Tcl_Obj *headersKeyPtr = Tcl_NewStringObj("headers", -1);
    Tcl_IncrRefCount(headersKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[2], headersKeyPtr, &headersPtr)) {
        Tcl_DecrRefCount(headersKeyPtr);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(headersKeyPtr);

    Tcl_Obj *multiValueHeadersPtr;
    Tcl_Obj *multiValueHeadersKeyPtr = Tcl_NewStringObj("multiValueHeaders", -1);
    Tcl_IncrRefCount(multiValueHeadersKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[2], multiValueHeadersKeyPtr, &multiValueHeadersPtr)) {
        Tcl_DecrRefCount(multiValueHeadersKeyPtr);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(multiValueHeadersKeyPtr);

    Tcl_Obj *bodyPtr;
    Tcl_Obj *bodyKeyPtr = Tcl_NewStringObj("body", -1);
    Tcl_IncrRefCount(bodyKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[2], bodyKeyPtr, &bodyPtr)) {
        Tcl_DecrRefCount(bodyKeyPtr);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(bodyKeyPtr);

    Tcl_Obj *isBase64EncodedPtr;
    Tcl_Obj *isBase64EncodedKeyPtr = Tcl_NewStringObj("isBase64Encoded", -1);
    Tcl_IncrRefCount(isBase64EncodedKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[2], isBase64EncodedKeyPtr, &isBase64EncodedPtr)) {
        Tcl_DecrRefCount(isBase64EncodedKeyPtr);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(isBase64EncodedKeyPtr);

    Tcl_DString ds;
    Tcl_DStringInit(&ds);
    Tcl_DStringAppend(&ds, "HTTP/1.1 ", 9);

    int status_code_length;
    const char *status_code = Tcl_GetStringFromObj(statusCodePtr, &status_code_length);
    Tcl_DStringAppend(&ds, status_code, status_code_length);

    // write each "header" from the "headers" dictionary to the ssl connection
    Tcl_Obj *keyPtr;
    Tcl_Obj *valuePtr;
    Tcl_DictSearch headersSearch;
    int done;
    if (headersPtr) {
        for (Tcl_DictObjFirst(interp, headersPtr, &headersSearch, &keyPtr, &valuePtr, &done);
             !done;
             Tcl_DictObjNext(&headersSearch, &keyPtr, &valuePtr, &done)) {
            // skip if "keyPtr" in "multiValueHeadersPtr" dictionary
            Tcl_Obj *listPtr;
            if (multiValueHeadersPtr) {
                Tcl_DictObjGet(interp, multiValueHeadersPtr, keyPtr, &listPtr);
                if (listPtr) {
                    continue;
                }
            }
            Tcl_DStringAppend(&ds, "\r\n", 2);
            int key_length;
            const char *key = Tcl_GetStringFromObj(keyPtr, &key_length);
            Tcl_DStringAppend(&ds, key, key_length);
            Tcl_DStringAppend(&ds, ": ", 2);
            int value_length;
            const char *value = Tcl_GetStringFromObj(valuePtr, &value_length);
            Tcl_DStringAppend(&ds, value, value_length);
        }
        Tcl_DictObjDone(&headersSearch);
    }

    if (multiValueHeadersPtr) {
        // write each "header" from the "multiValueHeaders" dictionary to the ssl connection
        Tcl_DictSearch mvHeadersSearch;
        for (Tcl_DictObjFirst(interp, multiValueHeadersPtr, &mvHeadersSearch, &keyPtr, &valuePtr, &done);
             !done;
             Tcl_DictObjNext(&mvHeadersSearch, &keyPtr, &valuePtr, &done)) {

            Tcl_DStringAppend(&ds, "\r\n", 2);
            int key_length;
            const char *key = Tcl_GetStringFromObj(keyPtr, &key_length);
            Tcl_DStringAppend(&ds, key, key_length);
            Tcl_DStringAppend(&ds, ": ", 2);

            // "valuePtr" is a list, iterate over its elements
            int list_length;
            Tcl_ListObjLength(interp, valuePtr, &list_length);
            for (int i = 0; i < list_length; i++) {
                Tcl_Obj *elemPtr;
                Tcl_ListObjIndex(interp, valuePtr, i, &elemPtr);
                int value_length;
                const char *value = Tcl_GetStringFromObj(elemPtr, &value_length);
                Tcl_DStringAppend(&ds, value, value_length);
                if (i < value_length - 1) {
                    Tcl_DStringAppend(&ds, ", ", 2);
                }
            }

        }
        Tcl_DictObjDone(&mvHeadersSearch);
    }

    if (conn->compression == GZIP_COMPRESSION) {
        // set the Content-Encoding header to "gzip"
        Tcl_DStringAppend(&ds, "\r\n", 2);
        Tcl_DStringAppend(&ds, "Content-Encoding: gzip", 22);
    }

    // write the body to the ssl connection
    int isBase64Encoded = 0;
    if (isBase64EncodedPtr) {
        Tcl_GetBooleanFromObj(interp, isBase64EncodedPtr, &isBase64Encoded);
    }

    int body_length = 0;
    char *body = NULL;
    int body_alloc = 0;
    int rc;
    if (isBase64Encoded) {

        int b64_body_length;
        const char *b64_body = Tcl_GetStringFromObj(bodyPtr, &b64_body_length);
        if (b64_body_length > 0) {
            body = Tcl_Alloc(3 * b64_body_length / 4 + 2);
            body_alloc = 1;
            if (base64_decode(b64_body, b64_body_length, body, &body_length)) {
                Tcl_DStringFree(&ds);
                Tcl_Free(body);
                SetResult("base64 decode error");
                return TCL_ERROR;
            }
        }
    } else {
        body = Tcl_GetStringFromObj(bodyPtr, &body_length);
    }

    Tcl_Obj *compressed = NULL;
    if (body_length > 0 && conn->compression == GZIP_COMPRESSION) {
        Tcl_Obj *baObj = Tcl_NewByteArrayObj(body, body_length);
        Tcl_IncrRefCount(baObj);
        if (Tcl_ZlibDeflate(interp, TCL_ZLIB_FORMAT_GZIP, baObj,
                            TCL_ZLIB_COMPRESS_FAST, NULL)) {
            Tcl_DecrRefCount(baObj);
            Tcl_DStringFree(&ds);
            if (body_alloc) {
                Tcl_Free(body);
            }
            SetResult("gzip compression error");
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(baObj);
        compressed = Tcl_GetObjResult(interp);
        Tcl_IncrRefCount(compressed);
        if (body_alloc) {
            Tcl_Free(body);
        }
        body = (char *) Tcl_GetByteArrayFromObj(compressed, &body_length);
        Tcl_ResetResult(interp);
    }

    Tcl_Obj *contentLengthPtr = Tcl_NewIntObj(body_length);
    Tcl_IncrRefCount(contentLengthPtr);
    int content_length_str_len;
    const char *content_length_str = Tcl_GetStringFromObj(contentLengthPtr, &content_length_str_len);
    Tcl_DStringAppend(&ds, "\r\n", 2);
    Tcl_DStringAppend(&ds, "Content-Length: ", 16);
    Tcl_DStringAppend(&ds, content_length_str, content_length_str_len);
    Tcl_DStringAppend(&ds, "\r\n\r\n", 4);
    Tcl_DecrRefCount(contentLengthPtr);

    if (body_length > 0) {
        Tcl_DStringAppend(&ds, body, body_length);
    }

    if (compressed != NULL) {
        Tcl_DecrRefCount(compressed);
    } else if (body_alloc) {
        // if "body" was allocated, free it
        // if we used compression, "body" was freed above
        Tcl_Free((char *) body);
    }


    int reply_length = Tcl_DStringLength(&ds);
    const char *reply = Tcl_DStringValue(&ds);

    rc = SSL_write(conn->ssl, reply, reply_length);

    Tcl_DStringFree(&ds);

    if (rc <= 0) {
        DBG(fprintf(stderr, "return_conn: SSL_write error (reply): %s\n", ssl_errors[SSL_get_error(conn->ssl, rc)]));
        tws_CloseConn(conn, conn_handle, 1);
        SetResult("return_conn: SSL_write error (reply)");
        return TCL_ERROR;
    }

    return TCL_OK;
}

static int tws_CloseConnCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "CloseConnCmd\n"));
    CheckArgs(2, 3, 1, "handle ?force_shutdown?");

    const char *conn_handle = Tcl_GetString(objv[1]);
    tws_conn_t *conn = tws_GetInternalFromConnName(conn_handle);
    if (!conn) {
        DBG(fprintf(stderr, "conn handle not found\n"));
        SetResult("close_conn: conn handle not found");
        return TCL_ERROR;
    }
    int force_shutdown = 0;
    if (objc == 3) {
        Tcl_GetBooleanFromObj(interp, objv[2], &force_shutdown);
    }
    if (TCL_OK != tws_CloseConn(conn, conn_handle, force_shutdown)) {
        SetResult("close conn failed");
        return TCL_ERROR;
    }
    return TCL_OK;
}

static int tws_InfoConnCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "InfoConnCmd\n"));
    CheckArgs(2, 2, 1, "conn_handle");

    const char *conn_handle = Tcl_GetString(objv[1]);
    tws_conn_t *conn = tws_GetInternalFromConnName(conn_handle);
    if (!conn) {
        SetResult("info_conn: conn handle not found");
        return TCL_ERROR;
    }

    Tcl_Obj *resultPtr = Tcl_NewDictObj();


    return TCL_OK;
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

static int
tws_UrlDecode(Tcl_Interp *interp, Tcl_Encoding encoding, const char *value, int value_length, Tcl_Obj *resultPtr) {
    // check if url decoding is needed, value is not '\0' terminated
    const char *p = value;
    const char *end = value + value_length;
    p = tws_strpbrk(value, end, "%+");

    // no url decoding is needed
    if (p == NULL) {
        Tcl_SetStringObj(resultPtr, value, value_length);
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
                SetResult("urldecode error: invalid %xx sequence");
                return TCL_ERROR;
            }
            if (!tws_IsCharOfType(value[0], CHAR_HEX) || !tws_IsCharOfType(value[1], CHAR_HEX)) {
                Tcl_Free(valuePtr);
                SetResult("urldecode error: invalid %xx sequence");
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
        SetResult("urldecode error: invalid utf-8 sequence");
        return TCL_ERROR;
    }
    Tcl_SetStringObj(resultPtr, dst, dstWrote);
    Tcl_Free(dst);
    Tcl_Free(valuePtr);
    return TCL_OK;
}

static int
tws_UrlEncode(Tcl_Interp *interp, int enc_flags, const char *value, int value_length, Tcl_Obj **valuePtrPtr) {
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
                char hex0 = hex_digits[(c >> 4) &
                                       0xF]; // Extract the high nibble of c and use it as an index in the lookup table
                char hex1 = hex_digits[c &
                                       0xF]; // Extract the low nibble of c and use it as an index in the lookup table

                *q++ = '%';
                *q++ = hex0;
                *q++ = hex1;
            }
        }
        p++;
    }
    *valuePtrPtr = Tcl_NewStringObj(valuePtr, q - valuePtr);
    Tcl_Free(valuePtr);
    return TCL_OK;
}

static int tws_AddQueryStringParameter(Tcl_Interp *interp, Tcl_Encoding encoding, Tcl_Obj *queryStringParametersPtr,
                                       Tcl_Obj *multivalueQueryStringParametersPtr, const char *key, const char *value,
                                       int value_length) {
    // check if "key" already exists in "queryStringParameters"
    Tcl_Obj *keyPtr = Tcl_NewStringObj(key, value - key - 1);
    Tcl_Obj *valuePtr = Tcl_NewStringObj("", 0);
    if (TCL_OK != tws_UrlDecode(interp, encoding, value, value_length, valuePtr)) {
        SetResult("query string urldecode error");
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

static int
tws_ParseQueryStringParameters(Tcl_Interp *interp, Tcl_Encoding encoding, Tcl_Obj *queryStringPtr, Tcl_Obj *resultPtr) {
    // parse "query_string" into "queryStringParameters" given that it is of the form "key1=value1&key2=value2&..."
    Tcl_Obj *queryStringParametersPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(queryStringParametersPtr);
    Tcl_Obj *multiValueQueryStringParametersPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(multiValueQueryStringParametersPtr);
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
            Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
            Tcl_DecrRefCount(queryStringParametersPtr);
            SetResult("query string parse error");
            return TCL_ERROR;
        }
        value = p + 1;
        while (p < end && *p != '&') {
            p++;
        }
        if (p == end) {
            if (TCL_OK !=
                tws_AddQueryStringParameter(interp, encoding, queryStringParametersPtr,
                                            multiValueQueryStringParametersPtr, key,
                                            value, p - value)) {
                Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
                Tcl_DecrRefCount(queryStringParametersPtr);
                SetResult("query string parse error");
                return TCL_ERROR;
            }
            break;
        }
        if (TCL_OK !=
            tws_AddQueryStringParameter(interp, encoding, queryStringParametersPtr, multiValueQueryStringParametersPtr,
                                        key,
                                        value, p - value)) {
            Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
            Tcl_DecrRefCount(queryStringParametersPtr);
            SetResult("query string parse error");
            return TCL_ERROR;
        }
        p++;
    }
    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("queryStringParameters", -1), queryStringParametersPtr);
    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("multiValueQueryStringParameters", -1),
                   multiValueQueryStringParametersPtr);
    Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
    Tcl_DecrRefCount(queryStringParametersPtr);
    return TCL_OK;
}

static int tws_ParsePathAndQueryString(Tcl_Interp *interp, Tcl_Encoding encoding, const char *url, int url_length,
                                       Tcl_Obj *resultPtr) {
    // parse "path" and "queryStringParameters" from "url"
    const char *p2 = url;
    while (p2 < url + url_length && *p2 != '\0') {
        if (*p2 == '?') {
            int path_length = p2 - url;
            Tcl_Obj *pathPtr = Tcl_NewStringObj("", 0);
            if (TCL_OK != tws_UrlDecode(interp, encoding, url, path_length, pathPtr)) {
                SetResult("path urldecode error");
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
    if (p2 == url + url_length) {
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("path", -1), Tcl_NewStringObj(url, url_length));
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("queryString", -1), Tcl_NewStringObj("", 0));
    }
    return TCL_OK;
}

static int tws_ParseRequestLine(Tcl_Interp *interp, Tcl_Encoding encoding, const char **currPtr, const char *end,
                                Tcl_Obj *resultPtr) {
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
        SetResult("request line parse error: no http method");
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
        SetResult("request line parse error: no url");
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
        SetResult("request line parse error: no version");
        return TCL_ERROR;
    }

    // parse "version" if we have NOT reached the end of line
    if (*curr != '\r' && *curr != '\n') {

        // collect non-space chars as third token
        while (curr < end && CHARTYPE(space, *curr) == 0) {
            curr++;
        }
        if (curr == end) {
            SetResult("request line parse error: while extracting version");
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
        free(key);

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
        free(value);

//        DBG(fprintf(stderr, "key=%s value=%s\n", key, value));

        // skip spaces until end of line denoted by "\r\n" or "\n"
        while (curr < end && CHARTYPE(space, *curr) != 0 && *curr != '\r' && *curr != '\n') {
            curr++;
        }

        // check if we reached the end
        if (curr == end) {
            if (TCL_OK != tws_AddHeader(interp, headersPtr, multiValueHeadersPtr, keyPtr, valuePtr)) {
                goto done;
            }
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
                goto done;
            }
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
            goto done;
        }

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
SetResult("headers parse error");
    return TCL_ERROR;
}

static int
tws_ParseBody(Tcl_Interp *interp, const char *curr, const char *end, Tcl_Obj *resultPtr, Tcl_Obj *contentLengthPtr,
              Tcl_Obj *contentTypePtr) {
    int contentLength;
    if (contentLengthPtr) {
        if (Tcl_GetIntFromObj(interp, contentLengthPtr, &contentLength) != TCL_OK) {
            SetResult("Content-Length must be an integer");
            return TCL_ERROR;
        }

        // check if we have enough bytes in the body
        if (end - curr < contentLength) {
            contentLength = end - curr;
        }
    } else {
        if (curr == end) {
            Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("isBase64Encoded", -1), Tcl_NewBooleanObj(0));
            Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("body", -1), Tcl_NewStringObj("", 0));
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
        size_t bodyLength;
        if (base64_encode(curr, contentLength, body, &bodyLength)) {
            Tcl_Free(body);
            SetResult("base64_encode failed");
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

    return TCL_OK;
}

static int tws_ParseRequest(Tcl_Interp *interp, Tcl_Encoding encoding, Tcl_DString *dsPtr, Tcl_Obj *dictPtr) {

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

    const char *request = Tcl_DStringValue(dsPtr);
    int length = Tcl_DStringLength(dsPtr);

    const char *curr = request;
    const char *end = request + length;

    // parse the first line of the request
    if (TCL_OK != tws_ParseRequestLine(interp, encoding, &curr, end, dictPtr)) {
        return TCL_ERROR;
    }

    Tcl_Obj *headersPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(headersPtr);
    Tcl_Obj *multiValueHeadersPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(multiValueHeadersPtr);
    if (TCL_OK != tws_ParseHeaders(interp, &curr, end, headersPtr, multiValueHeadersPtr)) {
        Tcl_DecrRefCount(multiValueHeadersPtr);
        Tcl_DecrRefCount(headersPtr);
        return TCL_ERROR;
    }
    Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("headers", -1), headersPtr);
    Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("multiValueHeaders", -1), multiValueHeadersPtr);

    // get "Content-Length" header
    Tcl_Obj *contentLengthPtr;
    Tcl_Obj *contentLengthKeyPtr = Tcl_NewStringObj("content-length", -1);
    Tcl_IncrRefCount(contentLengthKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, contentLengthKeyPtr, &contentLengthPtr)) {
        Tcl_DecrRefCount(multiValueHeadersPtr);
        Tcl_DecrRefCount(headersPtr);
        Tcl_DecrRefCount(contentLengthKeyPtr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(contentLengthKeyPtr);

    Tcl_Obj *contentTypePtr;
    Tcl_Obj *contentTypeKeyPtr = Tcl_NewStringObj("content-type", -1);
    Tcl_IncrRefCount(contentTypeKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, contentTypeKeyPtr, &contentTypePtr)) {
        Tcl_DecrRefCount(multiValueHeadersPtr);
        Tcl_DecrRefCount(headersPtr);
        Tcl_DecrRefCount(contentTypeKeyPtr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(contentTypeKeyPtr);

    Tcl_DecrRefCount(multiValueHeadersPtr);
    Tcl_DecrRefCount(headersPtr);

    tws_ParseBody(interp, curr, end, dictPtr, contentLengthPtr, contentTypePtr);

    return TCL_OK;
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

    Tcl_DString ds;
    Tcl_DStringInit(&ds);
    Tcl_DStringAppend(&ds, request, length);
    Tcl_Obj *resultPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(resultPtr);
    if (TCL_OK != tws_ParseRequest(interp, encoding, &ds, resultPtr)) {
        Tcl_DecrRefCount(resultPtr);
        Tcl_DStringFree(&ds);
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, resultPtr);
    Tcl_DecrRefCount(resultPtr);
    Tcl_DStringFree(&ds);
    return TCL_OK;

}

// gzip is enabled q-values greater than 0.001
static int tws_GzipAcceptEncoding(const char *accept_encoding, int accept_encoding_length) {
    // check if "accept_encoding" contains "gzip"
    const char *p = accept_encoding;
    const char *end = accept_encoding + accept_encoding_length;

    // use strstr to find the first "gzip" in "accept_encoding"
    p = strstr(p, "gzip");

    if (!p) {
        return 0;
    }

    p = p + 4;

    while (p < end) {
        switch (*p++) {
            case ',':
                return 1;
            case ';':
                goto quantity;
            case ' ':
                continue;
            default:
                return 0;
        }
    }

    return 1;

    quantity:
    while (p < end) {
        switch (*p++) {
            case 'q':
            case 'Q':
                goto equal;
            case ' ':
                continue;
            default:
                return 0;
        }
    }
    return 1;

    equal:
    if (p + 2 > end || *p++ != '=') {
        return 0;
    }

    double qvalue = strtod(p, NULL);
    return qvalue >= 0.001 && qvalue <= 1.0;
}

static int tws_ParseConnectionKeepalive(Tcl_Interp *interp, Tcl_Obj *headersPtr, int *keepalive) {
    Tcl_Obj *connectionPtr;
    Tcl_Obj *connectionKeyPtr = Tcl_NewStringObj("connection", -1);
    Tcl_IncrRefCount(connectionKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, connectionKeyPtr, &connectionPtr)) {
        Tcl_DecrRefCount(connectionKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(connectionKeyPtr);
    if (!connectionPtr) {
        return TCL_OK;
    }

    int connection_length;
    const char *connection = Tcl_GetStringFromObj(connectionPtr, &connection_length);
    if (connection_length == 10 && strncmp(connection, "keep-alive", 10) == 0) {
        *keepalive = 1;
    }
    return TCL_OK;
}

static int tws_ParseAcceptEncoding(Tcl_Interp *interp, Tcl_Obj *headersPtr, tws_compression_method_t *compression) {
    // parse "Accept-Encoding" header and set "compression" accordingly

    Tcl_Obj *acceptEncodingPtr;
    Tcl_Obj *acceptEncodingKeyPtr = Tcl_NewStringObj("accept-encoding", -1);
    Tcl_IncrRefCount(acceptEncodingKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, acceptEncodingKeyPtr, &acceptEncodingPtr)) {
        Tcl_DecrRefCount(acceptEncodingKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(acceptEncodingKeyPtr);
    if (!acceptEncodingPtr) {
        *compression = NO_COMPRESSION;
        return TCL_OK;
    }

    int accept_encoding_length;
    const char *accept_encoding = Tcl_GetStringFromObj(acceptEncodingPtr, &accept_encoding_length);

    /*
     * test first for the most common case "gzip,...":
     *   MSIE:    "gzip, deflate"
     *   Firefox: "gzip,deflate"
     *   Chrome:  "gzip,deflate,sdch"
     *   Safari:  "gzip, deflate"
     *   Opera:   "gzip, deflate"
     */

    if (accept_encoding_length >= 5 && strncmp(accept_encoding, "gzip,", 5) == 0) {
        *compression = GZIP_COMPRESSION;
        return TCL_OK;
    }

    if (tws_GzipAcceptEncoding(accept_encoding, accept_encoding_length)) {
        *compression = GZIP_COMPRESSION;
        return TCL_OK;
    }

    *compression = NO_COMPRESSION;
    return TCL_OK;
}

static int tws_ParseConnCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "ParseConnCmd\n"));
    CheckArgs(2, 3, 1, "conn_handle ?encoding_name?");


    const char *conn_handle = Tcl_GetString(objv[1]);
    tws_conn_t *conn = tws_GetInternalFromConnName(conn_handle);
    if (!conn) {
        SetResult("parse_conn: conn handle not found");
        return TCL_ERROR;
    }

    Tcl_Encoding encoding;
    if (objc == 3) {
        encoding = Tcl_GetEncoding(interp, Tcl_GetString(objv[2]));
    } else {
        encoding = Tcl_GetEncoding(interp, "utf-8");
    }

    Tcl_DString ds;
    Tcl_DStringInit(&ds);
    if (TCL_OK != tws_ReadConn(interp, conn, conn_handle, &ds)) {
        Tcl_DStringFree(&ds);
        return TCL_ERROR;
    }
    Tcl_Obj *resultPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(resultPtr);
    if (TCL_OK != tws_ParseRequest(interp, encoding, &ds, resultPtr)) {
        Tcl_DecrRefCount(resultPtr);
        Tcl_DStringFree(&ds);
        return TCL_ERROR;
    }

    Tcl_Obj *headersPtr;
    Tcl_Obj *headersKeyPtr = Tcl_NewStringObj("headers", -1);
    Tcl_IncrRefCount(headersKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, resultPtr, headersKeyPtr, &headersPtr)) {
        Tcl_DecrRefCount(headersKeyPtr);
        Tcl_DecrRefCount(resultPtr);
        Tcl_DStringFree(&ds);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(headersKeyPtr);

    if (headersPtr) {
        if (TCL_OK != tws_ParseConnectionKeepalive(interp, headersPtr, &conn->keepalive)) {
            Tcl_DecrRefCount(resultPtr);
            Tcl_DStringFree(&ds);
            return TCL_ERROR;
        }

        if (conn->keepalive && !conn->created_file_handler_p) {
            // notify the event loop to keep the connection alive
            tws_keepalive_event_t *evPtr = (tws_keepalive_event_t *) Tcl_Alloc(sizeof(tws_keepalive_event_t));
            evPtr->proc = tws_CreateFileHandlerForKeepaliveConn;
            evPtr->nextPtr = NULL;
            evPtr->clientData = (ClientData *) conn;
            Tcl_ThreadQueueEvent(conn->server->thread_id, (Tcl_Event *) evPtr, TCL_QUEUE_TAIL);
            Tcl_ThreadAlert(conn->server->thread_id);
        }

        if (TCL_OK != tws_ParseAcceptEncoding(interp, headersPtr, &conn->compression)) {
            Tcl_DecrRefCount(resultPtr);
            Tcl_DStringFree(&ds);
            return TCL_ERROR;
        }
    }

    Tcl_SetObjResult(interp, resultPtr);
    Tcl_DecrRefCount(resultPtr);
    Tcl_DStringFree(&ds);
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
    if (TCL_OK != tws_UrlDecode(interp, encoding, encoded_text, length, valuePtr)) {
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, valuePtr);
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

static void tws_ExitHandler(ClientData unused) {
    Tcl_MutexLock(&tws_ServerNameToInternal_HT_Mutex);
    Tcl_DeleteHashTable(&tws_ServerNameToInternal_HT);
    Tcl_MutexUnlock(&tws_ServerNameToInternal_HT_Mutex);

    Tcl_MutexLock(&tws_ConnNameToInternal_HT_Mutex);
    Tcl_DeleteHashTable(&tws_ConnNameToInternal_HT);
    Tcl_MutexUnlock(&tws_ConnNameToInternal_HT_Mutex);

    Tcl_MutexLock(&tws_HostNameToInternal_HT_Mutex);
    Tcl_DeleteHashTable(&tws_HostNameToInternal_HT);
    Tcl_MutexUnlock(&tws_HostNameToInternal_HT_Mutex);
}

void tws_InitModule() {
    if (!tws_ModuleInitialized) {
        sigset_t sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGPIPE);
        if (pthread_sigmask(SIG_BLOCK, &sigset, NULL)) {
            fprintf(stderr, "pthread_sigmask failed\n");
        }
        Tcl_MutexLock(&tws_ServerNameToInternal_HT_Mutex);
        Tcl_InitHashTable(&tws_ServerNameToInternal_HT, TCL_STRING_KEYS);
        Tcl_MutexUnlock(&tws_ServerNameToInternal_HT_Mutex);

        Tcl_MutexLock(&tws_ConnNameToInternal_HT_Mutex);
        Tcl_InitHashTable(&tws_ConnNameToInternal_HT, TCL_STRING_KEYS);
        Tcl_MutexUnlock(&tws_ConnNameToInternal_HT_Mutex);

        Tcl_MutexLock(&tws_HostNameToInternal_HT_Mutex);
        Tcl_InitHashTable(&tws_HostNameToInternal_HT, TCL_STRING_KEYS);
        Tcl_MutexUnlock(&tws_HostNameToInternal_HT_Mutex);

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
    Tcl_CreateObjCommand(interp, "::twebserver::return_conn", tws_ReturnConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::close_conn", tws_CloseConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::info_conn", tws_InfoConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::parse_request", tws_ParseRequestCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::parse_conn", tws_ParseConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::encode_uri_component", tws_EncodeURIComponentCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::decode_uri_component", tws_DecodeURIComponentCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::encode_query", tws_EncodeQueryCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::base64_encode", tws_Base64EncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::base64_decode", tws_Base64DecodeCmd, NULL, NULL);

    return Tcl_PkgProvide(interp, "twebserver", XSTR(VERSION));
}
