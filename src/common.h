/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#ifndef TWEBSERVER_COMMON_H
#define TWEBSERVER_COMMON_H

#include <tcl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>
#include <arpa/inet.h>

#ifndef TCL_SIZE_MAX
typedef int Tcl_Size;
# define Tcl_GetSizeIntFromObj Tcl_GetIntFromObj
# define Tcl_NewSizeIntObj Tcl_NewIntObj
# define TCL_SIZE_MAX      INT_MAX
# define TCL_SIZE_MODIFIER ""
#endif

#define XSTR(s) STR(s)
#define STR(s) #s

#ifdef DEBUG
# define DBG(x) x
#else
# define DBG(x)
#endif

#define ObjCmdProc(x) int (x)(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])

#define CheckArgs(min, max, n, msg) \
                 if ((objc < min) || (objc >max)) { \
                     Tcl_WrongNumArgs(interp, n, objv, msg); \
                     return TCL_ERROR; \
                 }

#define SetResult(str) Tcl_ResetResult(interp); \
                     Tcl_SetStringObj(Tcl_GetObjResult(interp), (str), -1)

#define CMD_SERVER_NAME(s, internal) sprintf((s), "_TWS_SERVER_%p", (internal))
#define CMD_CONN_NAME(s, internal) sprintf((s), "_TWS_CONN_%p", (internal))
#define CMD_ROUTER_NAME(s, internal) sprintf((s), "_TWS_ROUTER_%p", (internal))

#define CHARTYPE(what, c) (is ## what ((int)((unsigned char)(c))))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

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

typedef struct {
    Tcl_Obj *cmdPtr;
    Tcl_Obj *scriptPtr;
    Tcl_Obj *rootdirPtr;
    Tcl_ThreadId threadId;
    char handle[30];
    Tcl_HashTable listeners_HT;
    Tcl_ThreadId *conn_thread_ids;
    Tcl_Size max_request_read_bytes;
    Tcl_Size max_read_buffer_size;
    Tcl_Size backlog;
    int conn_timeout_millis;
    int garbage_collection_cleanup_threshold;
    int garbage_collection_interval_millis;
    int keepalive;  // whether keepalive is on or off
    int keepidle;   // the time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes
    int keepintvl;  // the time (in seconds) between individual keepalive probes
    int keepcnt;    // The maximum number of keepalive probes TCP should send before dropping the connection
    int num_threads; // number of threads to handle connections
    Tcl_Size thread_stacksize; // the stack size for each thread in bytes
    int thread_max_concurrent_conns; // the maximum number of concurrent connections per thread
    int gzip; // whether gzip compression is on or off
    Tcl_Size gzip_min_length; // the minimum length of the response body to apply gzip compression
    Tcl_HashTable gzip_types_HT; // the list of mime types to apply gzip compression
} tws_server_t;

// declare "tws_conn_t" here so that we can use it in the "tws_accept_ctx_t" struct
typedef struct tws_conn_t_ tws_conn_t;

typedef struct {
    int option_http;
    int server_fd;
    int epoll_fd;
    int port;
    Tcl_Interp *interp;
    tws_server_t *server;
    SSL_CTX *sslCtx;
    int (*read_fn)(tws_conn_t *conn, Tcl_DString *dsPtr, int size);
    int (*write_fn)(tws_conn_t *conn, const char *buf, int len);
    unsigned char ja3_fingerprint[16];
} tws_accept_ctx_t;

typedef enum tws_CompressionMethod {
    NO_COMPRESSION,
    GZIP_COMPRESSION,
    BROTLI_COMPRESSION
} tws_compression_method_t;

typedef struct tws_conn_t_ {
    tws_accept_ctx_t *accept_ctx;
    SSL *ssl;
    int client;
    Tcl_ThreadId threadId;
    long long latest_millis;
    // refactor the following into a flags field
    tws_compression_method_t compression;
    int keepalive;
    int created_file_handler_p;
    int todelete;
    struct tws_conn_t_ *prevPtr;
    struct tws_conn_t_ *nextPtr;
    // On a 64-bit system, a pointer address can be up to 16 hexadecimal digits long
    // plus the 0x prefix plus the conn prefix "_TWS_CONN_" plus the null terminator
    // that gives us 28 characters. We are making it 30 just to be on the safe side.
    char conn_handle[30];
    char client_ip[INET6_ADDRSTRLEN];

    Tcl_DString ds;
    Tcl_ThreadDataKey *dataKeyPtr;
    Tcl_Obj *requestDictPtr;
    Tcl_Size offset;
    Tcl_Size content_length;

    int error;
} tws_conn_t;

typedef struct {
    Tcl_EventProc *proc;    /* Function to call to service this event. */
    Tcl_Event *nextPtr;    /* Next in list of pending events, or NULL. */
    ClientData *clientData; // The pointer to the client data
} tws_event_t;

typedef struct {
    Tcl_EventProc *proc;    /* Function to call to service this event. */
    Tcl_Event *nextPtr;    /* Next in list of pending events, or NULL. */
    ClientData *routerClientData; // The pointer to the router client data
    ClientData *connClientData; // The pointer to the conn client data
} tws_router_event_t;

typedef struct {
    Tcl_Interp *interp;
    Tcl_Obj *cmdPtr;
    Tcl_Mutex *mutex;
    tws_server_t *server;
    tws_conn_t *firstConnPtr;
    tws_conn_t *lastConnPtr;
    int thread_index;
    int numConns;
    int numRequests;
    int epoll_fd;
} tws_thread_data_t;

typedef struct {
    Tcl_Condition condWait;
    tws_server_t *server;
    int thread_index;
} tws_thread_ctrl_t;

typedef struct tws_route_s {
    int type;
    int fast_star;
    int fast_slash;
    int option_prefix;
    int option_nocase;
    int option_strict;
    int http_method_len;
    char http_method[10];
    int path_len;
    char path[1024];
    int proc_name_len;
    char proc_name[128];
    Tcl_Obj *keys;
    char *pattern;
    struct tws_route_s *nextPtr;
} tws_route_t;

typedef struct tws_middleware_s {
    Tcl_Obj *enter_proc_ptr;
    Tcl_Obj *leave_proc_ptr;
    struct tws_middleware_s *nextPtr;
    struct tws_middleware_s *prevPtr;
} tws_middleware_t;

typedef struct {
    tws_route_t *firstRoutePtr;
    tws_route_t *lastRoutePtr;
    tws_middleware_t *firstMiddlewarePtr;
    tws_middleware_t *lastMiddlewarePtr;
    char handle[40];
} tws_router_t;

enum {
    TWS_DONE,
    TWS_ERROR,
    TWS_AGAIN
};

void tws_InitServerNameHT();
void tws_DeleteServerNameHT();
void tws_InitConnNameHT();
void tws_DeleteConnNameHT();
void tws_InitHostNameHT();
void tws_DeleteHostNameHT();
void tws_InitRouterNameHT();
void tws_DeleteRouterNameHT();

int tws_RegisterServerName(const char *name, tws_server_t *internal);
int tws_UnregisterServerName(const char *name);
tws_server_t * tws_GetInternalFromServerName(const char *name);
int tws_RegisterConnName(const char *name, tws_conn_t *internal);
int tws_UnregisterConnName(const char *name);
tws_conn_t *tws_GetInternalFromConnName(const char *name);
int tws_RegisterHostName(const char *name, SSL_CTX *internal);
int tws_UnregisterHostName(const char *name);
SSL_CTX *tws_GetInternalFromHostName(const char *name);
int tws_RegisterRouterName(const char *name, tws_router_t *internal);
int tws_UnregisterRouterName(const char *name);
tws_router_t *tws_GetInternalFromRouterName(const char *name);
char *tws_strndup(const char *s, size_t n);
int tws_IsBinaryType(const char *content_type, int content_type_length);

/*
 * Macros used to cast between pointers and integers (e.g. when storing an int
 * in ClientData), on 64-bit architectures they avoid gcc warning about "cast
 * to/from pointer from/to integer of different size".
 */

#if !defined(INT2PTR) && !defined(PTR2INT)
#   if defined(HAVE_INTPTR_T) || defined(intptr_t)
#	define INT2PTR(p) ((void *)(intptr_t)(p))
#	define PTR2INT(p) ((int)(intptr_t)(p))
#   else
#	define INT2PTR(p) ((void *)(p))
#	define PTR2INT(p) ((int)(p))
#   endif
#endif

#endif //TWEBSERVER_COMMON_H
