#include "library.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>



#ifdef DEBUG
# define DBG(x) x
#else
# define DBG(x)
#endif

#define CheckArgs(min,max,n,msg) \
                 if ((objc < min) || (objc >max)) { \
                     Tcl_WrongNumArgs(interp, n, objv, msg); \
                     return TCL_ERROR; \
                 }

#define CMD_SERVER_NAME(s,internal) sprintf((s), "_TWS_SERVER_%p", (internal))
#define CMD_CONN_NAME(s,internal) sprintf((s), "_TWS_CONN_%p", (internal))

static int           tws_ModuleInitialized;

static Tcl_HashTable tws_ServerNameToInternal_HT;
static Tcl_Mutex     tws_ServerNameToInternal_HT_Mutex;

static Tcl_HashTable tws_ConnNameToInternal_HT;
static Tcl_Mutex     tws_ConnNameToInternal_HT_Mutex;

static int           tws_ModuleInitialized;

typedef struct {
    SSL_CTX *sslCtx;
    Tcl_Obj *cmdPtr;
} tws_server_t;

typedef struct {
    SSL *ssl;
    int client;
} tws_conn_t;

//static char client_usage[] =
//        "Usage twsClient <method> <args>, where method can be:\n"
//        "  destroy\n"
//        "  listen port\n"
//;


static int
tws_RegisterServerName(const char *name, tws_server_t *internal) {

    Tcl_HashEntry *entryPtr;
    int newEntry;
    Tcl_MutexLock(&tws_ServerNameToInternal_HT_Mutex);
    entryPtr = Tcl_CreateHashEntry(&tws_ServerNameToInternal_HT, (char*)name, &newEntry);
    if (newEntry) {
        Tcl_SetHashValue(entryPtr, (ClientData)internal);
    }
    Tcl_MutexUnlock(&tws_ServerNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> RegisterServerName: name=%s internal=%p %s\n", name, internal, newEntry ? "entered into" : "already in"));

    return newEntry;
}

static int
tws_UnregisterServerName(const char *name) {

    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_ServerNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_ServerNameToInternal_HT, (char*)name);
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
    entryPtr = Tcl_FindHashEntry(&tws_ServerNameToInternal_HT, (char*)name);
    if (entryPtr != NULL) {
        internal = (tws_server_t *)Tcl_GetHashValue(entryPtr);
    }
    Tcl_MutexUnlock(&tws_ServerNameToInternal_HT_Mutex);

    return internal;
}

static int
tws_RegisterConnName(const char *name, tws_conn_t *internal) {

    Tcl_HashEntry *entryPtr;
    int newEntry;
    Tcl_MutexLock(&tws_ConnNameToInternal_HT_Mutex);
    entryPtr = Tcl_CreateHashEntry(&tws_ConnNameToInternal_HT, (char*)name, &newEntry);
    if (newEntry) {
        Tcl_SetHashValue(entryPtr, (ClientData)internal);
    }
    Tcl_MutexUnlock(&tws_ConnNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> RegisterConnName: name=%s internal=%p %s\n", name, internal, newEntry ? "entered into" : "already in"));

    return newEntry;
}

static int
tws_UnregisterConnName(const char *name) {

    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_ConnNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_ConnNameToInternal_HT, (char*)name);
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
    entryPtr = Tcl_FindHashEntry(&tws_ConnNameToInternal_HT, (char*)name);
    if (entryPtr != NULL) {
        internal = (tws_conn_t *)Tcl_GetHashValue(entryPtr);
    }
    Tcl_MutexUnlock(&tws_ConnNameToInternal_HT_Mutex);

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

tws_conn_t *tws_NewConn(SSL_CTX *sslCtx, int client) {
    SSL *ssl = SSL_new(sslCtx);
    SSL_set_fd(ssl, client);
    tws_conn_t *conn = (tws_conn_t *)Tcl_Alloc(sizeof(tws_conn_t));
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
    Tcl_Free((char *)conn);
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
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        tws_conn_t *conn = tws_NewConn(server->sslCtx, client);

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


//int tws_ClientObjCmd(ClientData  clientData, Tcl_Interp *interp, int objc, Tcl_Obj * const objv[]) {
//    static const char *clientMethods[] = {
//            "destroy",
//            "listen",
//            NULL
//    };
//
//    enum clientMethod {
//        m_destroy,
//        m_listen,
//    };
//
//    if (objc < 2) {
//        Tcl_ResetResult(interp);
//        Tcl_SetStringObj(Tcl_GetObjResult(interp), (client_usage), -1);
//        return TCL_ERROR;
//    }
//    Tcl_ResetResult(interp);
//
//    int methodIndex;
//    if (TCL_OK == Tcl_GetIndexFromObj(interp, objv[1], clientMethods, "method", 0, &methodIndex)) {
//        Tcl_ResetResult(interp);
//        const char *handle = Tcl_GetString(objv[0]);
//        switch ((enum clientMethod) methodIndex ) {
//            case m_destroy:
//                DBG(fprintf(stderr, "DestroyMethod\n"));
//                CheckArgs(2,2,1,"destroy");
//                return tws_Destroy(interp, handle);
//            case m_listen:
//                DBG(fprintf(stderr, "ListenMethod\n"));
//                CheckArgs(3,3,1,"listen port");
//                return tws_Listen(interp, handle, objv[2]);
//        }
//    }
//
//    Tcl_SetObjResult(interp, Tcl_NewStringObj("Unknown method", -1));
//    return TCL_ERROR;
//}

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

static int tws_CreateCmd(ClientData  clientData, Tcl_Interp *interp, int objc, Tcl_Obj * const objv[]) {
    DBG(fprintf(stderr, "CreateCmd\n"));
    CheckArgs(3, 3, 1, "config_dict cmd_name");

    Tcl_Obj *keyFilePtr;
    Tcl_Obj *certFilePtr;
    if (TCL_OK != Tcl_DictObjGet(interp, objv[1], Tcl_NewStringObj("key", -1), &keyFilePtr)) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("key not found in config_dict", -1));
        return TCL_ERROR;
    }
    if (TCL_OK != Tcl_DictObjGet(interp, objv[1], Tcl_NewStringObj("cert", -1), &certFilePtr)) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("cert not found in config_dict", -1));
        return TCL_ERROR;
    }
    SSL_CTX *ctx = create_context();
    configure_context(ctx, Tcl_GetString(keyFilePtr), Tcl_GetString(certFilePtr));

    tws_server_t *server_ctx = (tws_server_t *)Tcl_Alloc(sizeof(tws_server_t));
    server_ctx->sslCtx = ctx;
    server_ctx->cmdPtr = objv[2];
    Tcl_IncrRefCount(server_ctx->cmdPtr);

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

static int tws_DestroyCmd(ClientData  clientData, Tcl_Interp *interp, int objc, Tcl_Obj * const objv[]) {
    DBG(fprintf(stderr, "DestroyCmd\n"));
    CheckArgs(2, 2, 1, "handle");

    return tws_Destroy(interp, Tcl_GetString(objv[1]));

}

static int tws_ListenCmd(ClientData  clientData, Tcl_Interp *interp, int objc, Tcl_Obj * const objv[]) {
    DBG(fprintf(stderr, "ListenCmd\n"));
    CheckArgs(3, 3, 1, "handle port");

    return tws_Listen(interp, Tcl_GetString(objv[1]), objv[2]);

}

static int tws_ReadConnCmd(ClientData  clientData, Tcl_Interp *interp, int objc, Tcl_Obj * const objv[]) {
    DBG(fprintf(stderr, "ReadConnCmd\n"));
    CheckArgs(2, 3, 1, "handle ?max_buffer_size?");

    tws_conn_t *conn = tws_GetInternalFromConnName(Tcl_GetString(objv[1]));
    if (!conn) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("handle not found", -1));
        return TCL_ERROR;
    }

    long max_request_read_bytes = 1024*1024*10;
    int max_buffer_size = 1024*1024;
    if (objc == 3) {
        Tcl_GetIntFromObj(interp, objv[2], &max_buffer_size);
    }

    char *buf = (char *)Tcl_Alloc(max_buffer_size);
    long total_read = 0;
    int bytes_read = SSL_read(conn->ssl, buf, max_buffer_size);
    Tcl_Obj *resultPtr = Tcl_NewStringObj(buf, bytes_read);
    total_read += bytes_read;
    while(SSL_pending(conn->ssl) > 0) {
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

static int tws_WriteConnCmd(ClientData  clientData, Tcl_Interp *interp, int objc, Tcl_Obj * const objv[]) {
    DBG(fprintf(stderr, "WriteConnCmd\n"));
    CheckArgs(3, 3, 1, "handle text");

    tws_conn_t *conn = tws_GetInternalFromConnName(Tcl_GetString(objv[1]));
    if (!conn) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("handle not found", -1));
        return TCL_ERROR;
    }

    int length;
    const char *reply = Tcl_GetStringFromObj(objv[2], &length);
    SSL_write(conn->ssl, reply, length);

    return TCL_OK;

}

static int tws_CloseConnCmd(ClientData  clientData, Tcl_Interp *interp, int objc, Tcl_Obj * const objv[]) {
    DBG(fprintf(stderr, "CloseConnCmd\n"));
    CheckArgs(2, 2, 1, "handle");

    const char *conn_handle = Tcl_GetString(objv[1]);
    return tws_CloseConn(interp, conn_handle);
}


static void tws_ExitHandler(ClientData unused) {
}


void tws_InitModule() {
    if (!tws_ModuleInitialized) {
        Tcl_InitHashTable(&tws_ServerNameToInternal_HT, TCL_STRING_KEYS);
        Tcl_InitHashTable(&tws_ConnNameToInternal_HT, TCL_STRING_KEYS);
        Tcl_CreateThreadExitHandler(tws_ExitHandler, NULL);
        tws_ModuleInitialized = 1;
    }
}

int Tws_Init(Tcl_Interp *interp) {
    if (Tcl_InitStubs(interp, "8.6", 0) == NULL) {
        return TCL_ERROR;
    }

    tws_InitModule();

    Tcl_CreateNamespace(interp, "::tws", NULL, NULL);
    Tcl_CreateObjCommand(interp, "::tws::create_server", tws_CreateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::tws::destroy_server", tws_DestroyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::tws::listen_server", tws_ListenCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::tws::read_conn", tws_ReadConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::tws::write_conn", tws_WriteConnCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::tws::close_conn", tws_CloseConnCmd, NULL, NULL);

    return Tcl_PkgProvide(interp, "tws", "0.1");
}
