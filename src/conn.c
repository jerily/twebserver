/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include "conn.h"
#include "base64.h"
#include "request.h"
#include "https.h"

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/event.h>
#else

#include <sys/epoll.h>
#include <sys/ioctl.h>

#endif

#define MAX_EVENTS 100
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define MAX_BUFFER_SIZE 1024
#endif

static Tcl_Mutex tws_Thread_Mutex;
static Tcl_Mutex tws_Eval_Mutex;
static Tcl_ThreadDataKey dataKey;

long long current_time_in_millis() {
    // get current tv
    struct timeval tv;
    gettimeofday(&tv, NULL);
    // convert tv to milliseconds
    long long milliseconds = (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000LL);
    return milliseconds;
}


enum {
    TWS_MODE_BLOCKING,
    TWS_MODE_NONBLOCKING
};

tws_server_t *tws_GetCurrentServer() {
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));
    return dataPtr->server;
}

static int tws_SetBlockingMode(
        int fd,
        int mode            /* Either TWS_MODE_BLOCKING or TWS_MODE_NONBLOCKING. */
) {
    int flags = fcntl(fd, F_GETFL);

    if (mode == TWS_MODE_BLOCKING) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }
    return fcntl(fd, F_SETFL, flags);
}

static int create_socket(Tcl_Interp *interp, tws_server_t *server, int port, int *sock) {
    int server_fd;
    struct sockaddr_in6 server_addr;

    // create an IPv6 TCP socket
    server_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_fd < 0) {
        SetResult("Unable to create socket");
        return TCL_ERROR;
    }

    // disable IPV6_V6ONLY option
    int optval = 0;
    if (setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval)) == -1) {
        SetResult("Unable to set IPV6_V6ONLY");
        return TCL_ERROR;
    }

    // Set the close-on-exec flag so that the socket will not get inherited by child processes.
    fcntl(server_fd, F_SETFD, FD_CLOEXEC);

    int reuseaddr = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &reuseaddr, sizeof(reuseaddr))) {
        DBG(fprintf(stderr, "setsockopt SO_REUSEADDR failed"));
    }

    int reuseport = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, (char *) &reuseport, sizeof(reuseport))) {
        DBG(fprintf(stderr, "setsockopt SO_REUSEPORT failed"));
    }

    if (server->keepalive) {
        if (setsockopt(server_fd, SOL_SOCKET, SO_KEEPALIVE, &server->keepalive, sizeof(int))) {
            DBG(fprintf(stderr, "setsockopt SO_KEEPALIVE failed"));
        }

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#else
        // Set the TCP_KEEPIDLE option on the socket
        if (setsockopt(server_fd, IPPROTO_TCP, TCP_KEEPIDLE, &server->keepidle, sizeof(int)) == -1) {
            DBG(fprintf(stderr, "setsockopt TCP_KEEPIDLE failed"));
        }

        // Set the TCP_KEEPINTVL option on the socket
        if (setsockopt(server_fd, IPPROTO_TCP, TCP_KEEPINTVL, &server->keepintvl, sizeof(int)) == -1) {
            DBG(fprintf(stderr, "setsockopt TCP_KEEPINTVL failed"));
        }

        // Set the TCP_KEEPCNT option on the socket
        if (setsockopt(server_fd, IPPROTO_TCP, TCP_KEEPCNT, &server->keepcnt, sizeof(int)) == -1) {
            DBG(fprintf(stderr, "setsockopt TCP_KEEPCNT failed"));
        }
#endif
    }

    // bind the socket to the wildcard address and port 3005
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(port);

    if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        SetResult("Unable to bind");
        return TCL_ERROR;
    }

    int backlog = server->backlog; // the maximum length to which the  queue  of pending  connections  for sockfd may grow
    if (listen(server_fd, backlog) < 0) {
        SetResult("Unable to listen");
        return TCL_ERROR;
    }

    *sock = server_fd;
    return TCL_OK;
}

tws_conn_t *tws_NewConn(tws_accept_ctx_t *accept_ctx, int client, char client_ip[INET6_ADDRSTRLEN]) {
    tws_SetBlockingMode(client, TWS_MODE_NONBLOCKING);

    tws_conn_t *conn = (tws_conn_t *) Tcl_Alloc(sizeof(tws_conn_t));

    if (accept_ctx->option_http) {
        conn->ssl = NULL;
    } else {
        SSL *ssl = SSL_new(accept_ctx->sslCtx);
        if (ssl == NULL) {
            Tcl_Free((char *) conn);
            return NULL;
        }
        SSL_set_fd(ssl, client);
        SSL_set_accept_state(ssl);
        conn->ssl = ssl;
    }

    conn->accept_ctx = accept_ctx;
    conn->client = client;
    conn->compression = NO_COMPRESSION;
    conn->keepalive = 0;
    conn->created_file_handler_p = 0;
    conn->todelete = 0;
    conn->prevPtr = NULL;
    conn->nextPtr = NULL;
    memcpy(conn->client_ip, client_ip, INET6_ADDRSTRLEN);
    Tcl_DStringInit(&conn->ds);
    conn->dataKeyPtr = &dataKey;
    conn->requestDictPtr = NULL;
    conn->offset = 0;
    conn->content_length = 0;
    conn->error = 0;

    if (accept_ctx->server->num_threads > 0) {
//        fprintf(stderr, "tws_NewConn - num_threads: %d\n", accept_ctx->server->num_threads);
//        fprintf(stderr, "tws_NewConn - client: %d\n", client);
        conn->threadId = accept_ctx->server->conn_thread_ids[client % accept_ctx->server->num_threads];
    } else {
        conn->threadId = accept_ctx->server->threadId;
    }

    conn->latest_millis = current_time_in_millis();

    return conn;
}

static void tws_FreeConnWithThreadData(tws_conn_t *conn, tws_thread_data_t *dataPtr) {

    if (conn->prevPtr == NULL) {
        // the node to delete is the first node
        dataPtr->firstConnPtr = conn->nextPtr;
        if (dataPtr->firstConnPtr == NULL) {
            // only one node in the list
            dataPtr->lastConnPtr = NULL;
        } else {
            // update the previous pointer of the new first node
            dataPtr->firstConnPtr->prevPtr = NULL;
        }
    } else if (conn->nextPtr == NULL) {
        // the node to delete is the last node
        dataPtr->lastConnPtr = conn->prevPtr;
        dataPtr->lastConnPtr->nextPtr = NULL;
    } else {
        // the node to delete is neither first or last
        conn->prevPtr->nextPtr = conn->nextPtr;
        conn->nextPtr->prevPtr = conn->prevPtr;
    }

    SSL_free(conn->ssl);
    Tcl_DStringFree(&conn->ds);
    Tcl_Free((char *) conn);

    dataPtr->numConns--;
}

static void tws_FreeConn(tws_conn_t *conn) {
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));
    Tcl_MutexLock(dataPtr->mutex);
    tws_FreeConnWithThreadData(conn, dataPtr);
    Tcl_MutexUnlock(dataPtr->mutex);
}

static void tws_DeleteFileHandler(int fd) {
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    // Remove the server socket from the kqueue set
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    if (kevent(dataPtr->epoll_fd, &ev, 1, NULL, 0, NULL) == -1) {
        DBG(fprintf(stderr, "DeleteFileHandler: kevent failed, fd: %d\n", fd));
    }
#else
    // Remove the server socket from the epoll set
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (epoll_ctl(dataPtr->epoll_fd, EPOLL_CTL_DEL, fd, &ev) == -1) {
        DBG(fprintf(stderr, "DeleteFileHandler: epoll_ctl failed, fd: %d\n", fd));
    }
#endif
}

static int tws_DeleteFileHandlerForKeepaliveConn(Tcl_Event *evPtr, int flags) {
    tws_event_t *keepaliveEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) keepaliveEvPtr->clientData;
    DBG(fprintf(stderr, "DeleteFileHandlerForKeepaliveConn client=%d\n", conn->client));
    tws_DeleteFileHandler(conn->client);
//    Tcl_DeleteFileHandler(conn->client);
    tws_FreeConn(conn);
    return 1;
}

static void tws_KeepaliveConnHandler(void *data, int mask);

static void tws_ShutdownConn(tws_conn_t *conn, int force) {
    if (conn->todelete) {
        DBG(fprintf(stderr, "ShutdownConn - already marked for deletion\n"));
        return;
    }
    int shutdown_client = 1;
    if (!conn->accept_ctx->option_http) {
        if (!conn->error && SSL_is_init_finished(conn->ssl)) {
            DBG(fprintf(stderr, "SSL_is_init_finished: true\n"));
            int rc = SSL_shutdown(conn->ssl);
            DBG(fprintf(stderr, "first SSL_shutdown rc: %d\n", rc));
            if (rc == 0) {
                shutdown(conn->client, SHUT_RDWR);
                shutdown_client = 0;
                rc = SSL_shutdown(conn->ssl);
                DBG(fprintf(stderr, "second SSL_shutdown rc: %d\n", rc));
            }
        }
    }
    DBG(fprintf(stderr, "shutdown_client: %d\n", shutdown_client));
    if (shutdown_client) {
        if (shutdown(conn->client, SHUT_RDWR)) {
            DBG(
                    int error;
                    getsockopt(conn->client, SOL_SOCKET, SO_ERROR, &error, &(socklen_t) {sizeof(error)});
                    fprintf(stderr, "failed to shutdown client: %d error=%d\n", conn->client, error)
            );
        }
    }
    if (close(conn->client)) {
        DBG(fprintf(stderr, "close failed\n"));
    }

    if (conn->created_file_handler_p == 1) {
        DBG(fprintf(stderr, "schedule deletion of file handler client: %d\n", conn->client));

        // notify the event loop to delete the file handler for keepalive
        tws_event_t *evPtr = (tws_event_t *) Tcl_Alloc(sizeof(tws_event_t));
        evPtr->proc = tws_DeleteFileHandlerForKeepaliveConn;
        evPtr->nextPtr = NULL;
        evPtr->clientData = (ClientData *) conn;
        Tcl_ThreadQueueEvent(conn->threadId, (Tcl_Event *) evPtr, TCL_QUEUE_TAIL);
        Tcl_ThreadAlert(conn->threadId);
    }
    DBG(fprintf(stderr, "done shutdown\n"));
}

static int tws_CleanupConnections(Tcl_Event *evPtr, int flags) {
    tws_event_t *cleanupEvPtr = (tws_event_t *) evPtr;
    tws_server_t *server = (tws_server_t *) cleanupEvPtr->clientData;

    Tcl_ThreadId currentThreadId = Tcl_GetCurrentThread();
    DBG(fprintf(stderr, "CleanupConnections currentThreadId=%p\n", currentThreadId));

    long long milliseconds = current_time_in_millis();

    int count = 0;
    int count_mark_for_deletion = 0;

    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));
    Tcl_MutexLock(dataPtr->mutex);
    tws_conn_t *curr_conn = dataPtr->firstConnPtr;
    while (curr_conn != NULL) {
        // shouldn't be the case but we check anyway
        if (curr_conn->threadId != currentThreadId) {
            fprintf(stderr, "wrong thread cleanup conn->threadId=%p currentThreadId=%p\n", curr_conn->threadId,
                    currentThreadId);
            continue;
        }

        if (curr_conn->todelete) {
            DBG(fprintf(stderr, "CleanupConnections - deleting conn - client: %d\n", curr_conn->client));

            tws_FreeConnWithThreadData(curr_conn, dataPtr);

            DBG(fprintf(stderr, "CleanupConnections - deleted conn - client: %d\n", curr_conn->client));
        } else {
            long long elapsed = milliseconds - curr_conn->latest_millis;
            if (elapsed > curr_conn->accept_ctx->server->conn_timeout_millis) {
                if (tws_UnregisterConnName(curr_conn->conn_handle)) {
                    DBG(fprintf(stderr, "CleanupConnections - mark connection for deletion\n"));
                    // ShutdownConn needed to trigger tws_DeleteFileHandlerForKeepaliveConn
                    tws_ShutdownConn(curr_conn, 2);
                    // if keepalive, tws_DeleteFileHandlerForKeepaliveConn will free the connection
                    if (!curr_conn->keepalive) {
                        curr_conn->todelete = 1;
                        count_mark_for_deletion++;
                    }
                }
            }
        }
        count++;

        curr_conn = curr_conn->nextPtr;
    }
    Tcl_MutexUnlock(dataPtr->mutex);

    DBG(fprintf(stderr, "reviewed count: %d marked_for_deletion: %d\n", count, count_mark_for_deletion));
//    Tcl_CreateTimerHandler(server->garbage_collection_interval_millis, tws_CleanupConnections, clientData);

    return 1;
}

static void tws_CreateFileHandler(int fd, ClientData clientData) {
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    // Add the server socket to the kqueue set
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_READ, EV_ADD, 0, 0, clientData);
    if (kevent(dataPtr->epoll_fd, &ev, 1, NULL, 0, NULL) == -1) {
        DBG(fprintf(stderr, "CreateFileHandler: kevent failed, fd: %d\n", fd));
    }
#else
    // Add the server socket to the epoll set
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    ev.data.ptr = clientData;
    if (epoll_ctl(dataPtr->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        DBG(fprintf(stderr, "CreateFileHandler: epoll_ctl failed, fd: %d\n", fd));
    }
#endif
}

static int tws_CreateFileHandlerForKeepaliveConn(Tcl_Event *evPtr, int flags) {
    DBG(fprintf(stderr, "CreateFileHandlerForKeepaliveConn\n"));
    tws_event_t *keepaliveEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) keepaliveEvPtr->clientData;
    DBG(fprintf(stderr, "CreateFileHandlerForKeepaliveConn conn=%p client=%d\n", conn, conn->client));
    tws_CreateFileHandler(conn->client, conn);

    return 1;
}

int tws_CloseConn(tws_conn_t *conn, int force) {
    DBG(fprintf(stderr, "CloseConn - client: %d force: %d keepalive: %d handler: %d\n", conn->client, force,
                conn->keepalive, conn->created_file_handler_p));

    Tcl_DStringSetLength(&conn->ds, 0);
    conn->offset = 0;
    conn->content_length = 0;
    conn->requestDictPtr = NULL;

    if (force) {
        if (tws_UnregisterConnName(conn->conn_handle)) {
            tws_ShutdownConn(conn, force);
            // if keepalive, then we need to delete the file handler
            // so, we free the connection there as well
            if (!conn->keepalive) {
                tws_FreeConn(conn);
            }
        }
    } else {
        if (!conn->keepalive) {
            if (tws_UnregisterConnName(conn->conn_handle)) {
                tws_ShutdownConn(conn, 2);
                tws_FreeConn(conn);
            }
        } else {
            if (!conn->created_file_handler_p) {
                conn->created_file_handler_p = 1;
                // notify the event loop to keep the connection alive
                tws_event_t *evPtr = (tws_event_t *) Tcl_Alloc(sizeof(tws_event_t));
                evPtr->proc = tws_CreateFileHandlerForKeepaliveConn;
                evPtr->nextPtr = NULL;
                evPtr->clientData = (ClientData *) conn;
                Tcl_ThreadQueueEvent(conn->threadId, (Tcl_Event *) evPtr, TCL_QUEUE_TAIL);
                Tcl_ThreadAlert(conn->threadId);
            }
        }
    }

    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));
    dataPtr->numRequests = (dataPtr->numRequests + 1) % INT_MAX;
    tws_server_t *server = conn->accept_ctx->server;
    // make sure that garbage collection does not start the same time on all threads
    int thread_pivot = dataPtr->thread_index * (server->garbage_collection_cleanup_threshold / server->num_threads);
    if (dataPtr->numRequests % server->garbage_collection_cleanup_threshold == thread_pivot) {
        tws_event_t *evPtr = (tws_event_t *) Tcl_Alloc(sizeof(tws_event_t));
        evPtr->proc = tws_CleanupConnections;
        evPtr->nextPtr = NULL;
        evPtr->clientData = (ClientData *) conn->accept_ctx->server;
        Tcl_ThreadQueueEvent(conn->threadId, (Tcl_Event *) evPtr, TCL_QUEUE_TAIL);
        Tcl_ThreadAlert(conn->threadId);
    }

    return TCL_OK;
}

static int tws_HandleProcessing(tws_conn_t *conn) {
    DBG(fprintf(stderr, "HandleProcessingEventInThread: %s\n", conn->conn_handle));
    tws_accept_ctx_t *accept_ctx = conn->accept_ctx;

    tws_thread_data_t *dataPtr;
    Tcl_Interp *interp;
    Tcl_Obj *cmdPtr;
    if (accept_ctx->server->num_threads > 0) {
        // Get a pointer to the thread data for the current thread
        dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));
        // Get the interp from the thread data
        interp = dataPtr->interp;
        cmdPtr = dataPtr->cmdPtr;
    } else {
        // Get the interp from the main thread
        interp = accept_ctx->interp;
        cmdPtr = accept_ctx->server->cmdPtr;
        Tcl_MutexLock(&tws_Eval_Mutex);
    }

    Tcl_Obj *const connPtr = Tcl_NewStringObj(conn->conn_handle, -1);
    Tcl_Obj *const addrPtr = Tcl_NewStringObj(conn->client_ip, -1);
    Tcl_Obj *const portPtr = Tcl_NewIntObj(accept_ctx->port);
    Tcl_Obj *const cmdobjv[] = {cmdPtr, connPtr, addrPtr, portPtr, NULL};

    Tcl_IncrRefCount(connPtr);
    Tcl_IncrRefCount(addrPtr);
    Tcl_IncrRefCount(portPtr);
    Tcl_ResetResult(interp);
    if (TCL_OK != Tcl_EvalObjv(interp, 4, cmdobjv, TCL_EVAL_INVOKE)) {
        fprintf(stderr, "error evaluating script sock=%d\n", conn->client);
        fprintf(stderr, "error=%s\n", Tcl_GetString(Tcl_GetObjResult(interp)));
        fprintf(stderr, "%s\n", Tcl_GetVar2(interp, "::errorInfo", NULL, TCL_GLOBAL_ONLY));
        Tcl_DecrRefCount(connPtr);
        Tcl_DecrRefCount(addrPtr);
        Tcl_DecrRefCount(portPtr);

        if (accept_ctx->server->num_threads == 0) {
            Tcl_MutexUnlock(&tws_Eval_Mutex);
        }

        return 1;
    }
    Tcl_DecrRefCount(connPtr);
    Tcl_DecrRefCount(addrPtr);
    Tcl_DecrRefCount(portPtr);


    if (accept_ctx->server->num_threads > 0) {
        Tcl_MutexUnlock(dataPtr->mutex);
    } else {
        Tcl_MutexUnlock(&tws_Eval_Mutex);
    }

    return 1;
}

static int tws_HandleProcessingEventInThread(Tcl_Event *evPtr, int flags) {
    tws_event_t *connEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) connEvPtr->clientData;
    return tws_HandleProcessing(conn);
}

static void tws_ThreadQueueProcessingEvent(tws_conn_t *conn) {
    DBG(fprintf(stderr, "ThreadQueueConnEvent - threadId: %p\n", conn->threadId));
    tws_event_t *connEvPtr = (tws_event_t *) Tcl_Alloc(sizeof(tws_event_t));
    connEvPtr->proc = tws_HandleProcessingEventInThread;
    connEvPtr->nextPtr = NULL;
    connEvPtr->clientData = (ClientData *) conn;
    Tcl_QueueEvent((Tcl_Event *) connEvPtr, TCL_QUEUE_TAIL);
    Tcl_ThreadAlert(conn->threadId);
    DBG(fprintf(stderr, "ThreadQueueConnEvent done - threadId: %p\n", conn->threadId));
}

int tws_HandleHttpHandshake(tws_conn_t *conn) {
    tws_ThreadQueueProcessingEvent(conn);
    return 1;
}

int tws_HandleSslHandshake(tws_conn_t *conn) {
    ERR_clear_error();
    int rc = SSL_accept(conn->ssl);
    if (rc <= 0) {
        int err = SSL_get_error(conn->ssl, rc);
        if (err == SSL_ERROR_WANT_READ) {
            DBG(fprintf(stderr, "HandleHandshake: SSL_ERROR_WANT_READ\n"));
            return 0;
        }
        fprintf(stderr, "SSL_accept <= 0 client: %d err=%s\n", conn->client, ssl_errors[err]);
        conn->error = 1;
        tws_CloseConn(conn, 1);
        ERR_print_errors_fp(stderr);
        return 1;
    } else {
        DBG(fprintf(stderr, "HandleHandshake: success\n"));
        tws_ThreadQueueProcessingEvent(conn);
        return 1;
    }
}

static int tws_HandleHandshakeEventInThread(Tcl_Event *evPtr, int flags) {
    tws_event_t *connEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) connEvPtr->clientData;
    DBG(fprintf(stderr, "HandleHandshakeEventInThread: %s\n", conn->conn_handle));
    int result = conn->accept_ctx->option_http ? tws_HandleHttpHandshake(conn) : tws_HandleSslHandshake(conn);
    if (!result) {
        Tcl_ThreadAlert(conn->threadId);
    }
    return result;
}

static void tws_ThreadQueueHandshakeEvent(tws_conn_t *conn) {
    DBG(fprintf(stderr, "ThreadQueueHandshakeEvent - threadId: %p\n", conn->threadId));
    tws_event_t *connEvPtr = (tws_event_t *) Tcl_Alloc(sizeof(tws_event_t));
    connEvPtr->proc = tws_HandleHandshakeEventInThread;
    connEvPtr->nextPtr = NULL;
    connEvPtr->clientData = (ClientData *) conn;
    Tcl_QueueEvent((Tcl_Event *) connEvPtr, TCL_QUEUE_TAIL);
    Tcl_ThreadAlert(conn->threadId);
    DBG(fprintf(stderr, "ThreadQueueHandshakeEvent done - threadId: %p\n", conn->threadId));
}

static void tws_HandleConn(tws_conn_t *conn) {
    DBG(fprintf(stderr, "HandleConn client: %d\n", conn->client));
    tws_ThreadQueueHandshakeEvent(conn);
}

int tws_ReturnConn(Tcl_Interp *interp, tws_conn_t *conn, Tcl_Obj *const responseDictPtr, Tcl_Encoding encoding) {

    if (!conn->accept_ctx) {
        SetResult("ReturnConn called on deleted conn");
        return TCL_ERROR;
    }

    if (conn->error) {
        SetResult("ReturnConn called on conn with error");
        return TCL_ERROR;
    }

    Tcl_Obj *statusCodePtr;
    Tcl_Obj *statusCodeKeyPtr = Tcl_NewStringObj("statusCode", -1);
    Tcl_IncrRefCount(statusCodeKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, responseDictPtr, statusCodeKeyPtr, &statusCodePtr)) {
        Tcl_DecrRefCount(statusCodeKeyPtr);
        tws_CloseConn(conn, 1);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(statusCodeKeyPtr);
    if (!statusCodePtr) {
        tws_CloseConn(conn, 1);
        SetResult("statusCode not found");
        return TCL_ERROR;
    }

    Tcl_Obj *headersPtr;
    Tcl_Obj *headersKeyPtr = Tcl_NewStringObj("headers", -1);
    Tcl_IncrRefCount(headersKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, responseDictPtr, headersKeyPtr, &headersPtr)) {
        Tcl_DecrRefCount(headersKeyPtr);
        tws_CloseConn(conn, 1);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(headersKeyPtr);

    Tcl_Obj *multiValueHeadersPtr;
    Tcl_Obj *multiValueHeadersKeyPtr = Tcl_NewStringObj("multiValueHeaders", -1);
    Tcl_IncrRefCount(multiValueHeadersKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, responseDictPtr, multiValueHeadersKeyPtr, &multiValueHeadersPtr)) {
        Tcl_DecrRefCount(multiValueHeadersKeyPtr);
        tws_CloseConn(conn, 1);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(multiValueHeadersKeyPtr);

    Tcl_Obj *bodyPtr;
    Tcl_Obj *bodyKeyPtr = Tcl_NewStringObj("body", -1);
    Tcl_IncrRefCount(bodyKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, responseDictPtr, bodyKeyPtr, &bodyPtr)) {
        Tcl_DecrRefCount(bodyKeyPtr);
        tws_CloseConn(conn, 1);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(bodyKeyPtr);

    if (!bodyPtr) {
        tws_CloseConn(conn, 1);
        SetResult("body not found");
        return TCL_ERROR;
    }

    Tcl_Obj *isBase64EncodedPtr;
    Tcl_Obj *isBase64EncodedKeyPtr = Tcl_NewStringObj("isBase64Encoded", -1);
    Tcl_IncrRefCount(isBase64EncodedKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, responseDictPtr, isBase64EncodedKeyPtr, &isBase64EncodedPtr)) {
        Tcl_DecrRefCount(isBase64EncodedKeyPtr);
        tws_CloseConn(conn, 1);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(isBase64EncodedKeyPtr);

    Tcl_DString ds;
    Tcl_DStringInit(&ds);
    Tcl_DStringAppend(&ds, "HTTP/1.1 ", 9);

    Tcl_Size status_code_length;
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
            Tcl_Size key_length;
            const char *key = Tcl_GetStringFromObj(keyPtr, &key_length);
            Tcl_DStringAppend(&ds, key, key_length);
            Tcl_DStringAppend(&ds, ": ", 2);
            Tcl_Size value_length;
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
            Tcl_Size key_length;
            const char *key = Tcl_GetStringFromObj(keyPtr, &key_length);
            Tcl_DStringAppend(&ds, key, key_length);
            Tcl_DStringAppend(&ds, ": ", 2);

            // "valuePtr" is a list, iterate over its elements
            Tcl_Size list_length;
            Tcl_ListObjLength(interp, valuePtr, &list_length);
            for (int i = 0; i < list_length; i++) {
                Tcl_Obj *elemPtr;
                Tcl_ListObjIndex(interp, valuePtr, i, &elemPtr);
                Tcl_Size value_length;
                const char *value = Tcl_GetStringFromObj(elemPtr, &value_length);
                Tcl_DStringAppend(&ds, value, value_length);
                if (i < value_length - 1) {
                    Tcl_DStringAppend(&ds, ", ", 2);
                }
            }

        }
        Tcl_DictObjDone(&mvHeadersSearch);
    }

    // write the body to the ssl connection
    int isBase64Encoded = 0;
    if (isBase64EncodedPtr) {
        Tcl_GetBooleanFromObj(interp, isBase64EncodedPtr, &isBase64Encoded);
    }

    Tcl_Size body_length = 0;
    char *body = NULL;
    int body_alloc = 0;
    int rc;
    if (isBase64Encoded) {

        Tcl_Size b64_body_length;
        const char *b64_body = Tcl_GetStringFromObj(bodyPtr, &b64_body_length);
        if (b64_body_length > 0) {
            body = Tcl_Alloc(3 * b64_body_length / 4 + 2);
            body_alloc = 1;
            if (base64_decode(b64_body, b64_body_length, body, &body_length)) {
                Tcl_DStringFree(&ds);
                Tcl_Free(body);
                tws_CloseConn(conn, 1);
                SetResult("base64 decode error");
                return TCL_ERROR;
            }
        }
    } else {
        body = (char *) Tcl_GetStringFromObj(bodyPtr, &body_length);
    }

    int gzip_p = conn->accept_ctx->server->gzip
                 && conn->compression == GZIP_COMPRESSION
                 && body_length > 0
                 && body_length >= conn->accept_ctx->server->gzip_min_length;

    if (gzip_p && headersPtr) {
        // get Content-Type header
        Tcl_Obj *contentTypePtr;
        Tcl_Obj *contentTypeKeyPtr = Tcl_NewStringObj("Content-Type", -1);
        Tcl_IncrRefCount(contentTypeKeyPtr);
        if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, contentTypeKeyPtr, &contentTypePtr)) {
            Tcl_DecrRefCount(contentTypeKeyPtr);
            Tcl_DStringFree(&ds);
            if (body_alloc) {
                Tcl_Free(body);
            }
            tws_CloseConn(conn, 1);
            SetResult("error reading from dict");
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(contentTypeKeyPtr);

        // check if content type is in gzip_types_HT
        if (contentTypePtr) {
            Tcl_Size contentTypeLength;
            char *contentType = Tcl_GetStringFromObj(contentTypePtr, &contentTypeLength);
            if (contentTypeLength > 0) {
                // find the first ";" in contentType
                char *p = memchr(contentType, ';', contentTypeLength);
                if (p) {
                    contentType = tws_strndup(contentType, p - contentType);
                }
                DBG(fprintf(stderr, "contentType: %s\n", contentType));
                Tcl_HashEntry *entry = Tcl_FindHashEntry(&conn->accept_ctx->server->gzip_types_HT, contentType);
                if (!entry) {
                    DBG(fprintf(stderr, "not found contentType: %s\n", contentType));
                    gzip_p = 0;
                }
                if (p) {
                    Tcl_Free(contentType);
                }
            }
        }
    }

    if (gzip_p) {
        // set the Content-Encoding header to "gzip"
        Tcl_DStringAppend(&ds, "\r\n", 2);
        Tcl_DStringAppend(&ds, "Content-Encoding: gzip", 22);
    }

    Tcl_Obj *compressed = NULL;
    if (gzip_p) {

        Tcl_Obj *baObj = Tcl_NewByteArrayObj(body, body_length);
        Tcl_IncrRefCount(baObj);
        if (Tcl_ZlibDeflate(interp, TCL_ZLIB_FORMAT_GZIP, baObj,
                            TCL_ZLIB_COMPRESS_FAST, NULL)) {
            Tcl_DecrRefCount(baObj);
            Tcl_DStringFree(&ds);
            if (body_alloc) {
                Tcl_Free(body);
            }
            tws_CloseConn(conn, 1);
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
    Tcl_Size content_length_str_len;
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

    rc = conn->accept_ctx->write_fn(conn, reply, reply_length);

    Tcl_DStringFree(&ds);

    if (rc == TWS_ERROR) {
        conn->error = 1;
        tws_CloseConn(conn, 1);
        SetResult("return_conn: write error (reply)");
        return TCL_ERROR;
    }

    if (TCL_OK != tws_CloseConn(conn, 0)) {
        SetResult("return_conn: close_conn failed");
        return TCL_ERROR;
    }

    return TCL_OK;
}


int tws_InfoConnCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
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

Tcl_ThreadCreateType tws_HandleConnThread(ClientData clientData) {

    tws_thread_ctrl_t *ctrl = (tws_thread_ctrl_t *) clientData;

    DBG(Tcl_ThreadId threadId = Tcl_GetCurrentThread());
    Tcl_Mutex mutex;
    // Get a pointer to the thread data for the current thread
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));
    // Create a new interp for this thread and store it in the thread data
    dataPtr->interp = Tcl_CreateInterp();
    dataPtr->cmdPtr = Tcl_DuplicateObj(ctrl->server->cmdPtr);
    dataPtr->mutex = &mutex;
    dataPtr->server = ctrl->server;
    dataPtr->thread_index = ctrl->thread_index;
    dataPtr->numRequests = 0;
    dataPtr->numConns = 0;
    dataPtr->firstConnPtr = NULL;
    dataPtr->lastConnPtr = NULL;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    dataPtr->epoll_fd = kqueue();
#else
    dataPtr->epoll_fd = epoll_create1(0);
#endif

    Tcl_IncrRefCount(dataPtr->cmdPtr);

    DBG(fprintf(stderr, "created interp=%p\n", dataPtr->interp));

    Tcl_InitMemory(dataPtr->interp);
    if (TCL_OK != Tcl_Init(dataPtr->interp)) {
        DBG(fprintf(stderr, "error initializing Tcl\n"));
        Tcl_FinalizeThread();
        Tcl_ExitThread(TCL_ERROR);
        return TCL_THREAD_CREATE_RETURN;
    }
    if (TCL_OK != Tcl_EvalObj(dataPtr->interp, ctrl->server->scriptPtr)) {
        fprintf(stderr, "error evaluating init script\n");
        fprintf(stderr, "error=%s\n", Tcl_GetString(Tcl_GetObjResult(dataPtr->interp)));
        fprintf(stderr, "%s\n", Tcl_GetVar2(dataPtr->interp, "::errorInfo", NULL, TCL_GLOBAL_ONLY));
        Tcl_FinalizeThread();
        Tcl_ExitThread(TCL_ERROR);
        return TCL_THREAD_CREATE_RETURN;
    }

    // create a file handler for the epoll fd for this thread
    Tcl_CreateFileHandler(dataPtr->epoll_fd, TCL_READABLE, tws_KeepaliveConnHandler, NULL);

    // make sure that garbage collection does not start the same time on all threads
//    int first_timer_millis =
//            ctrl->thread_index * (ctrl->server->garbage_collection_interval_millis / ctrl->server->num_threads);
//    Tcl_CreateTimerHandler(first_timer_millis, tws_CleanupConnections, ctrl->server);

    // notify the main thread that we are done initializing
    Tcl_ConditionNotify(&ctrl->condWait);

    DBG(fprintf(stderr, "HandleConnThread: in (%p) - first timer millis: %d\n", threadId, first_timer_millis));
    while (1) {
        Tcl_DoOneEvent(TCL_ALL_EVENTS);
    }
    Tcl_FinalizeThread();
    Tcl_ExitThread(TCL_OK);
    DBG(fprintf(stderr, "HandleConnThread: out (%p)\n", threadId));
    TCL_THREAD_CREATE_RETURN;
}

static int tws_HandleConnEventInThread(Tcl_Event *evPtr, int flags) {
    DBG(fprintf(stderr, "HandleConnEventInThread\n"));
    tws_event_t *connEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) connEvPtr->clientData;

    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));
    Tcl_MutexLock(dataPtr->mutex);

    // prefer to refuse connection if we are over the limit
    // this is to cap memory usage
    int thread_limit = conn->accept_ctx->server->thread_max_concurrent_conns;
    if (thread_limit > 0 && dataPtr->numConns >= thread_limit) {
        shutdown(conn->client, SHUT_RDWR);
        close(conn->client);
        SSL_free(conn->ssl);
        Tcl_Free((char *) conn);
        Tcl_MutexUnlock(dataPtr->mutex);
        return 1;
    }

    if (dataPtr->firstConnPtr == NULL) {
        dataPtr->firstConnPtr = conn;
        dataPtr->lastConnPtr = conn;
    } else {
        dataPtr->lastConnPtr->nextPtr = conn;
        conn->prevPtr = dataPtr->lastConnPtr;
        dataPtr->lastConnPtr = conn;
    }
    dataPtr->numConns++;

    //    fprintf(stderr, "HandleConnEventInThread - numConns: %d FD_SETSIZE: %d thread_limit: %d\n", dataPtr->numConns, FD_SETSIZE, thread_limit);

    Tcl_MutexUnlock(dataPtr->mutex);

    tws_HandleConn(conn);
    return 1;
}

static void tws_ThreadQueueConnEvent(tws_conn_t *conn) {
    DBG(fprintf(stderr, "ThreadQueueConnEvent - threadId: %p\n", conn->threadId));
    tws_event_t *connEvPtr = (tws_event_t *) Tcl_Alloc(sizeof(tws_event_t));
    connEvPtr->proc = tws_HandleConnEventInThread;
    connEvPtr->nextPtr = NULL;
    connEvPtr->clientData = (ClientData *) conn;
    Tcl_ThreadQueueEvent(conn->threadId, (Tcl_Event *) connEvPtr, TCL_QUEUE_TAIL);
    Tcl_ThreadAlert(conn->threadId);
    DBG(fprintf(stderr, "ThreadQueueConnEvent done - threadId: %p\n", conn->threadId));
}

static void tws_KeepaliveConnHandler(void *data, int mask) {
    DBG(fprintf(stderr, "KeepaliveConnHandler mask=%d\n", mask));

    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    struct kevent events[MAX_EVENTS];
    int nfds = kevent(dataPtr->epoll_fd, NULL, 0, events, MAX_EVENTS, NULL);
    if (nfds == -1) {
        DBG(fprintf(stderr, "KeepaliveConnHandler: kevent failed"));
        return;
    }
#else
    struct epoll_event events[MAX_EVENTS];
    int nfds = epoll_wait(dataPtr->epoll_fd, events, MAX_EVENTS, -1);
    if (nfds == -1) {
        DBG(fprintf(stderr, "KeepaliveConnHandler: epoll_wait failed"));
        return;
    }
#endif

    for (int i = 0; i < nfds; i++) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        tws_conn_t *conn = (tws_conn_t *) events[i].udata;
#else
        tws_conn_t *conn = (tws_conn_t *) events[i].data.ptr;
#endif
        DBG(fprintf(stderr, "KeepaliveConnHandler - keepalive client: %d %s\n", conn->client, conn->conn_handle));
        conn->latest_millis = current_time_in_millis();
        tws_HandleConn(conn);
    }

}

void tws_AcceptConn(void *data, int mask) {
    tws_accept_ctx_t *accept_ctx = (tws_accept_ctx_t *) data;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    struct kevent events[MAX_EVENTS];
    int nfds = kevent(accept_ctx->epoll_fd, NULL, 0, events, MAX_EVENTS, NULL);
    if (nfds == -1) {
        DBG(fprintf(stderr, "kevent failed"));
        return;
    }
#else
    struct epoll_event events[MAX_EVENTS];
    int nfds = epoll_wait(accept_ctx->epoll_fd, events, MAX_EVENTS, -1);
    if (nfds == -1) {
        DBG(fprintf(stderr, "epoll_wait failed"));
        return;
    }
#endif
    DBG(fprintf(stderr, "-------------------tws_AcceptConn, nfds: %d\n", nfds));

    for (int i = 0; i < nfds; i++) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        if (events[i].ident == accept_ctx->server_fd) {
#else
        if (events[i].data.fd == accept_ctx->server_fd) {
#endif
            // new incoming connection

            struct sockaddr_in6 client_addr;
            unsigned int len = sizeof(client_addr);
            int client = accept(accept_ctx->server_fd, (struct sockaddr *) &client_addr, &len);
            DBG(fprintf(stderr, "client: %d\n", client));
            if (client < 0) {
                DBG(fprintf(stderr, "Unable to accept"));
                return;
            }

            // get the client IP address
            char client_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &client_addr.sin6_addr, client_ip, sizeof(client_ip));
            DBG(fprintf(stderr, "Client connected from %s\n", client_ip));

            tws_conn_t *conn = tws_NewConn(accept_ctx, client, client_ip);
            if (conn == NULL) {
                shutdown(client, SHUT_WR);
                shutdown(client, SHUT_RD);
                close(client);
                DBG(fprintf(stderr, "Unable to create SSL connection"));
                return;
            }

            CMD_CONN_NAME(conn->conn_handle, conn);
            tws_RegisterConnName(conn->conn_handle, conn);

            if (accept_ctx->server->num_threads > 0) {
                tws_ThreadQueueConnEvent(conn);
            } else {
                tws_HandleConn(conn);
            }

        } else {
            // data available on an existing connection
            // we do not have any as each thread has its own epoll instance
        }

    }
}

int tws_Listen(Tcl_Interp *interp, tws_server_t *server, int option_http, Tcl_Obj *portPtr) {

    int port;
    if (Tcl_GetIntFromObj(interp, portPtr, &port) != TCL_OK) {
        SetResult("port must be an integer");
        return TCL_ERROR;
    }

    int server_fd;
    if (TCL_OK != create_socket(interp, server, port, &server_fd)) {
        return TCL_ERROR;
    }
    if (server_fd < 0) {
        SetResult("Unable to create socket");
        return TCL_ERROR;
    }

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    // Create a kqueue instance
    int epoll_fd = kqueue();
    if (epoll_fd == -1) {
        SetResult("Unable to create kqueue instance");
        return TCL_ERROR;
    }
#else
    // Create an epoll instance
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        SetResult("Unable to create epoll instance");
        return TCL_ERROR;
    }
#endif


#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    // Add the server socket to the kqueue set
    struct kevent ev;
    EV_SET(&ev, server_fd, EVFILT_READ, EV_ADD, 0, 0, server_fd);
    if (kevent(epoll_fd, &ev, 1, NULL, 0, NULL) == -1) {
        SetResult("Unable to add server socket to kqueue set");
        return TCL_ERROR;
    }
#else
    // Add the server socket to the epoll set
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
        SetResult("Unable to add server socket to epoll set");
        return TCL_ERROR;
    }
#endif

    tws_accept_ctx_t *accept_ctx = (tws_accept_ctx_t *) Tcl_Alloc(sizeof(tws_accept_ctx_t));

    if (option_http) {
        accept_ctx->read_fn = tws_ReadHttpConnAsync;
        accept_ctx->write_fn = tws_WriteHttpConnAsync;
    } else {

        accept_ctx->read_fn = tws_ReadSslConnAsync;
        accept_ctx->write_fn = tws_WriteSslConnAsync;

        // it is an https server, so we need to create an SSL_CTX
        if (TCL_OK != tws_CreateSslContext(interp, &accept_ctx->sslCtx)) {
            Tcl_Free((char *) accept_ctx);
            return TCL_ERROR;
        }
        SSL_CTX_set_client_hello_cb(accept_ctx->sslCtx, tws_ClientHelloCallback, accept_ctx);
    }

    accept_ctx->option_http = option_http;
    accept_ctx->server_fd = server_fd;
    accept_ctx->epoll_fd = epoll_fd;
    accept_ctx->port = port;
    accept_ctx->interp = interp;
    accept_ctx->server = server;

    // add accept_ctx to listeners_HT hash table
    int newEntry;
    Tcl_HashEntry *entry = Tcl_CreateHashEntry(&server->listeners_HT, INT2PTR(server_fd), &newEntry);
    if (newEntry) {
        Tcl_SetHashValue(entry, accept_ctx);
    } else {
        Tcl_Free((char *) accept_ctx);
        SetResult("Unable to add server socket to listeners_HT");
        return TCL_ERROR;
    }


    if (server->num_threads == 0) {
        server->conn_thread_ids = NULL;
    } else {
        server->conn_thread_ids = (Tcl_ThreadId *) Tcl_Alloc(sizeof(Tcl_ThreadId) * server->num_threads);
        for (int i = 0; i < server->num_threads; i++) {
            Tcl_MutexLock(&tws_Thread_Mutex);
            Tcl_ThreadId id;
            tws_thread_ctrl_t ctrl;
            ctrl.condWait = NULL;
            ctrl.server = server;
            ctrl.thread_index = i;
            if (TCL_OK !=
                Tcl_CreateThread(&id, tws_HandleConnThread, &ctrl, server->thread_stacksize, TCL_THREAD_NOFLAGS)) {
                Tcl_MutexUnlock(&tws_Thread_Mutex);
                SetResult("Unable to create thread");
                return TCL_ERROR;
            }
            server->conn_thread_ids[i] = id;

            // Wait for the thread to start because it is using something on our stack!
            Tcl_ConditionWait(&ctrl.condWait, &tws_Thread_Mutex, NULL);
            Tcl_MutexUnlock(&tws_Thread_Mutex);
            Tcl_ConditionFinalize(&ctrl.condWait);
            DBG(fprintf(stderr, "Listen - created thread: %p\n", id));
        }
    }

    Tcl_CreateFileHandler(epoll_fd, TCL_READABLE, tws_AcceptConn, accept_ctx);

    if (server->num_threads == 0) {
        tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));
        dataPtr->interp = NULL;
        dataPtr->cmdPtr = NULL;
        dataPtr->mutex = &tws_Thread_Mutex;
        dataPtr->server = server;
        dataPtr->thread_index = 0;
        dataPtr->numRequests = 0;
        dataPtr->numConns = 0;
        dataPtr->firstConnPtr = NULL;
        dataPtr->lastConnPtr = NULL;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        dataPtr->epoll_fd = kqueue();
#else
        dataPtr->epoll_fd = epoll_create1(0);
#endif
        Tcl_CreateFileHandler(dataPtr->epoll_fd, TCL_READABLE, tws_KeepaliveConnHandler, NULL);

//        Tcl_CreateTimerHandler(server->garbage_collection_interval_millis, tws_CleanupConnections, server);
    }
    return TCL_OK;
}
