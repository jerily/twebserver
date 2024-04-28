/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
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
#include <netdb.h>
#else

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <netdb.h>

#endif

#define MAX_EVENTS 100
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define MAX_BUFFER_SIZE 1024
#endif

static Tcl_Mutex tws_Thread_Mutex;
static Tcl_ThreadDataKey dataKey;


enum {
    TWS_MODE_BLOCKING,
    TWS_MODE_NONBLOCKING
};

static int tws_HandleRecv(tws_conn_t *conn);
static void tws_KeepaliveConnHandler(void *data, int mask);
static int tws_AddConnToThreadList(tws_conn_t *conn);

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

static int bind_socket(Tcl_Interp *interp, int server_fd, const char *host, int port_num) {
    if (host != NULL) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        struct hostent *hostent = gethostbyname(host);
        if (hostent == NULL) {
            SetResult("Unable to get host by name");
            return TCL_ERROR;
        }
#else
        struct hostent *hostent;
        struct hostent hostent_data;
        char buffer[1024];
        int herrno;
        int ret = gethostbyname_r(host, &hostent_data, buffer, sizeof(buffer), &hostent, &herrno);
        if (ret != 0) {
            SetResult("Unable to get host by name");
            return TCL_ERROR;
        }
#endif

        // Iterate over the list of IP addresses returned by gethostbyname
        for (int i = 0; hostent->h_addr_list[i] != NULL; i++) {
            struct sockaddr_in6 ipv6_addr;
            struct sockaddr_in ipv4_addr;

            if (hostent->h_addrtype == AF_INET6) {
                fprintf(stderr, "ipv6\n");
                memset(&ipv6_addr, 0, sizeof(ipv6_addr));
                ipv6_addr.sin6_family = AF_INET6;
                ipv6_addr.sin6_port = htons(port_num);

                memcpy(&ipv6_addr.sin6_addr, hostent->h_addr_list[i], sizeof(struct in6_addr));

            } else if (hostent->h_addrtype == AF_INET) {
                memset(&ipv4_addr, 0, sizeof(ipv4_addr));
                ipv4_addr.sin_family = AF_INET;
                ipv4_addr.sin_port = htons(port_num);

                memcpy(&ipv4_addr.sin_addr.s_addr, hostent->h_addr_list[i], sizeof(struct in_addr));

                //convert it to an ipv6 mapped ipv4 address
                struct in6_addr v4addr = IN6ADDR_ANY_INIT;
                v4addr.s6_addr[10] = 0xff;
                v4addr.s6_addr[11] = 0xff;
                v4addr.s6_addr[12] = ipv4_addr.sin_addr.s_addr & 0xff;
                v4addr.s6_addr[13] = (ipv4_addr.sin_addr.s_addr >> 8) & 0xff;
                v4addr.s6_addr[14] = (ipv4_addr.sin_addr.s_addr >> 16) & 0xff;
                v4addr.s6_addr[15] = (ipv4_addr.sin_addr.s_addr >> 24) & 0xff;

                memset(&ipv6_addr, 0, sizeof(ipv6_addr));
                ipv6_addr.sin6_family = AF_INET6;
                ipv6_addr.sin6_port = htons(port_num);
                memcpy(&ipv6_addr.sin6_addr, &v4addr, sizeof(struct in6_addr));

            } else {
                SetResult("Unknown address family");
                return TCL_ERROR;
            }

            if (bind(server_fd, (struct sockaddr *) &ipv6_addr, sizeof(ipv6_addr)) < 0) {
                SetResult("Unable to bind ipv6 addr");
                return TCL_ERROR;
            }

            // print address
            char straddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ipv6_addr.sin6_addr, straddr, INET6_ADDRSTRLEN);
            fprintf(stderr, "bind successful on ipv6 addr: %s\n", straddr);

        }
    } else {
        // bind the socket to the wildcard address and the specified port
        struct sockaddr_in6 server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin6_family = AF_INET6;
        server_addr.sin6_addr = in6addr_any;
        server_addr.sin6_port = htons(port_num);

        if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
            SetResult("Unable to bind ipv4 addr");
            return TCL_ERROR;
        }
    }
    return TCL_OK;
}

static int create_socket(Tcl_Interp *interp, tws_server_t *server, const char *host, const char *port, int *server_sock) {
    int server_fd;

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

    int port_num = atoi(port);
    if (TCL_OK != bind_socket(interp, server_fd, host, port_num)) {
        return TCL_ERROR;
    }

    tws_SetBlockingMode(server_fd, TWS_MODE_NONBLOCKING);

    int backlog = server->backlog; // the maximum length to which the  queue  of pending  connections  for sockfd may grow
    if (listen(server_fd, backlog) < 0) {
        SetResult("Unable to listen");
        return TCL_ERROR;
    }

    tws_SetBlockingMode(server_fd, TWS_MODE_NONBLOCKING);

    *server_sock = server_fd;
    return TCL_OK;
}

static int create_epoll_fd(Tcl_Interp *interp, int server_fd, int *epoll_sock) {
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
    EV_SET(&ev, server_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, server_fd);
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

    *epoll_sock = epoll_fd;
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
    conn->handle_conn_fn = accept_ctx->handle_conn_fn;
    conn->client = client;
    conn->compression = NO_COMPRESSION;
    conn->keepalive = 0;
    conn->created_file_handler_p = 0;
    conn->ready = 0;
    conn->handshaked = 0;
    conn->processed = 0;
    conn->todelete = 0;
    conn->shutdown = 0;
    conn->prevPtr = NULL;
    conn->nextPtr = NULL;
    memcpy(conn->client_ip, client_ip, INET6_ADDRSTRLEN);
    Tcl_DStringInit(&conn->ds);
    conn->dataKeyPtr = &dataKey;
    conn->requestDictPtr = NULL;
    conn->offset = 0;
    conn->content_length = 0;
    conn->error = 0;
    conn->blank_line_offset = 0;

//        fprintf(stderr, "tws_NewConn - num_threads: %d\n", accept_ctx->server->num_threads);
//        fprintf(stderr, "tws_NewConn - client: %d\n", client);
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    conn->threadId = accept_ctx->conn_thread_ids[client % accept_ctx->num_threads];
#else
    conn->threadId = Tcl_GetCurrentThread();
#endif
    conn->start_read_millis = current_time_in_millis();
    conn->latest_millis = conn->start_read_millis;

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
    Tcl_MutexLock(&tws_Thread_Mutex);
    tws_FreeConnWithThreadData(conn, dataPtr);
    Tcl_MutexUnlock(&tws_Thread_Mutex);
}

static void tws_DeleteFileHandler(int fd) {
    DBG(fprintf(stderr, "DeleteFileHandler client: %d\n", fd));

    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    // Remove the server socket from the kqueue set
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    if (kevent(dataPtr->epoll_fd, &ev, 1, NULL, 0, NULL) == -1) {
        fprintf(stderr, "DeleteFileHandler: kevent failed, fd: %d\n", fd);
    }
#else
    // Remove the server socket from the epoll set
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (epoll_ctl(dataPtr->epoll_fd, EPOLL_CTL_DEL, fd, &ev) == -1) {
        fprintf(stderr, "DeleteFileHandler: epoll_ctl failed, fd: %d\n", fd);
    }
#endif
}


static void tws_ShutdownConn(tws_conn_t *conn, int force) {
    if (conn->todelete) {
        DBG(fprintf(stderr, "ShutdownConn - already marked for deletion\n"));
        return;
    }


    if (conn->created_file_handler_p == 1) {
        tws_DeleteFileHandler(conn->client);
        conn->created_file_handler_p = 0;
    }

    conn->shutdown = 1;
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

    DBG(fprintf(stderr, "done shutdown\n"));
}

static int tws_CleanupConnections(Tcl_Event *evPtr, int flags) {
    Tcl_ThreadId currentThreadId = Tcl_GetCurrentThread();
    DBG(fprintf(stderr, "CleanupConnections currentThreadId=%p\n", currentThreadId));

    long long milliseconds = current_time_in_millis();

    int count = 0;
    int count_mark_for_deletion = 0;

    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));
    Tcl_MutexLock(&tws_Thread_Mutex);
    tws_conn_t *curr_conn = dataPtr->firstConnPtr;
    while (curr_conn != NULL) {

        if (curr_conn->todelete || curr_conn->shutdown) {
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
    Tcl_MutexUnlock(&tws_Thread_Mutex);

    DBG(fprintf(stderr, "reviewed count: %d marked_for_deletion: %d\n", count, count_mark_for_deletion));

    return 1;
}

static void tws_CreateFileHandler(int fd, ClientData clientData) {
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    // Add the server socket to the kqueue set
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, clientData);
    if (kevent(dataPtr->epoll_fd, &ev, 1, NULL, 0, NULL) == -1) {
        fprintf(stderr, "CreateFileHandler: kevent failed, fd: %d\n", fd);
    }
#else
    // Add the server socket to the epoll set
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    ev.data.ptr = clientData;
    if (epoll_ctl(dataPtr->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        fprintf(stderr, "CreateFileHandler: epoll_ctl failed, fd: %d\n", fd);
    }
#endif
}

static int tws_HandleCreateFileHandlerEventInThread(Tcl_Event *evPtr, int flags) {
    DBG(fprintf(stderr, "CreateFileHandlerForKeepaliveConn\n"));
    tws_event_t *keepaliveEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) keepaliveEvPtr->clientData;
    DBG(fprintf(stderr, "CreateFileHandlerForKeepaliveConn conn=%p client=%d\n", conn, conn->client));
    tws_CreateFileHandler(conn->client, conn);

    return 1;
}

void tws_QueueCleanupEvent() {
    Tcl_ThreadId currentThreadId = Tcl_GetCurrentThread();
    DBG(fprintf(stderr, "ThreadQueueCleanupEvent: %p\n", currentThreadId));
    Tcl_Event *evPtr = (Tcl_Event *) Tcl_Alloc(sizeof(Tcl_Event));
    evPtr->proc = tws_CleanupConnections;
    evPtr->nextPtr = NULL;
    Tcl_QueueEvent((Tcl_Event *) evPtr, TCL_QUEUE_TAIL);
    Tcl_ThreadAlert(currentThreadId);
}

void tws_QueueCreateFileHandlerEvent(tws_conn_t *conn) {
    tws_event_t *evPtr = (tws_event_t *) Tcl_Alloc(sizeof(tws_event_t));
    evPtr->proc = tws_HandleCreateFileHandlerEventInThread;
    evPtr->nextPtr = NULL;
    evPtr->clientData = (ClientData *) conn;
    Tcl_QueueEvent((Tcl_Event *) evPtr, TCL_QUEUE_TAIL);
    Tcl_ThreadAlert(conn->threadId);
}

int tws_CloseConn(tws_conn_t *conn, int force) {
    DBG(fprintf(stderr, "CloseConn - client: %d force: %d keepalive: %d handler: %d\n", conn->client, force,
                conn->keepalive, conn->created_file_handler_p));

    Tcl_DStringSetLength(&conn->ds, 0);
    conn->offset = 0;
    conn->blank_line_offset = 0;
    conn->content_length = 0;
    conn->requestDictPtr = NULL;
    conn->handle_conn_fn = tws_HandleRecv;
    conn->shutdown = 0;
    conn->ready = 0;
    conn->processed = 0;
//    conn->handshaked = 0;

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
                tws_QueueCreateFileHandlerEvent(conn);
            }
        }
    }

    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));
    dataPtr->numRequests = (dataPtr->numRequests + 1) % INT_MAX;
    tws_server_t *server = conn->accept_ctx->server;
    // make sure that garbage collection does not start the same time on all threads
    if (dataPtr->numRequests % server->garbage_collection_cleanup_threshold == dataPtr->thread_pivot) {
        tws_QueueCleanupEvent();
    }

    return TCL_OK;
}

static int tws_HandleProcessing(tws_conn_t *conn) {
    DBG(fprintf(stderr, "HandleProcessing: %s\n", conn->conn_handle));

    tws_accept_ctx_t *accept_ctx = conn->accept_ctx;

    tws_thread_data_t *dataPtr;
    Tcl_Interp *interp;
    Tcl_Obj *cmdPtr;

    // Get a pointer to the thread data for the current thread
    dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));
    // Get the interp from the thread data
    interp = dataPtr->interp;
    cmdPtr = dataPtr->cmdPtr;

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
        return 1;
    }
    Tcl_DecrRefCount(connPtr);
    Tcl_DecrRefCount(addrPtr);
    Tcl_DecrRefCount(portPtr);

    return 1;
}

static int tws_HandleRecv(tws_conn_t *conn);

static int tws_ParseTopPart(Tcl_Interp *interp, tws_conn_t *conn) {

    Tcl_Encoding encoding = Tcl_GetEncoding(interp, "utf-8");
    Tcl_Obj *req_dict_ptr = Tcl_NewDictObj();
    Tcl_IncrRefCount(req_dict_ptr);
    if (TCL_OK != tws_ParseRequest(interp, encoding, &conn->ds, req_dict_ptr, &conn->offset)) {
        Tcl_DecrRefCount(req_dict_ptr);
        return TCL_ERROR;
    }

    // get content-length from header

    Tcl_Obj *headersPtr;
    Tcl_Obj *headersKeyPtr = Tcl_NewStringObj("headers", -1);
    Tcl_IncrRefCount(headersKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, req_dict_ptr, headersKeyPtr, &headersPtr)) {
        Tcl_DecrRefCount(req_dict_ptr);
        Tcl_DecrRefCount(headersKeyPtr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(headersKeyPtr);

    if (headersPtr) {
        // get "Content-Length" header
        Tcl_Obj *contentLengthPtr;
        Tcl_Obj *contentLengthKeyPtr = Tcl_NewStringObj("content-length", -1);
        Tcl_IncrRefCount(contentLengthKeyPtr);
        if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, contentLengthKeyPtr, &contentLengthPtr)) {
            Tcl_DecrRefCount(req_dict_ptr);
            Tcl_DecrRefCount(contentLengthKeyPtr);
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(contentLengthKeyPtr);

        if (contentLengthPtr) {
            if (TCL_OK != Tcl_GetSizeIntFromObj(interp, contentLengthPtr, &conn->content_length)) {
                Tcl_DecrRefCount(req_dict_ptr);
                return TCL_ERROR;
            }
        }

        if (conn->accept_ctx->server->keepalive) {
            if (TCL_OK != tws_ParseConnectionKeepalive(interp, headersPtr, &conn->keepalive)) {
                Tcl_DecrRefCount(req_dict_ptr);
                return TCL_ERROR;
            }
        }

        if (conn->accept_ctx->server->gzip) {
            if (TCL_OK != tws_ParseAcceptEncoding(interp, headersPtr, &conn->compression)) {
                Tcl_DecrRefCount(req_dict_ptr);
                return TCL_ERROR;
            }
        }

    }
    conn->requestDictPtr = req_dict_ptr;
    return TCL_OK;
}

static int tws_ParseBottomPart(Tcl_Interp *interp, tws_conn_t *conn, Tcl_Obj *req_dict_ptr) {
    DBG(fprintf(stderr, "parse bottom part\n"));

    Tcl_Obj *headersPtr;
    Tcl_Obj *headersKeyPtr = Tcl_NewStringObj("headers", -1);
    Tcl_IncrRefCount(headersKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, req_dict_ptr, headersKeyPtr, &headersPtr)) {
        Tcl_DecrRefCount(headersKeyPtr);
        goto handle_error;
    }
    Tcl_DecrRefCount(headersKeyPtr);

    if (headersPtr) {
        if (conn->content_length > 0) {
            const char *remaining_unprocessed_ptr = Tcl_DStringValue(&conn->ds) + conn->offset;
            const char *end = Tcl_DStringValue(&conn->ds) + Tcl_DStringLength(&conn->ds);
            tws_ParseBody(interp, remaining_unprocessed_ptr, end, headersPtr, req_dict_ptr);
        }
    }

    return TCL_OK;
    handle_error:
    return TCL_ERROR;
}

static int tws_FoundBlankLine(tws_conn_t *conn) {
    const char *s = Tcl_DStringValue(&conn->ds);
    const char *p = s + conn->blank_line_offset;
    const char *end = s + Tcl_DStringLength(&conn->ds);
    while (p < end) {
        if ((p < end - 3 && *p == '\r' && *(p + 1) == '\n' && *(p + 2) == '\r' && *(p + 3) == '\n') || (p < end - 1 && *p == '\n' && *(p + 1) == '\n')) {
            conn->blank_line_offset = p - s - 1;
            return 1;
        }
        p++;
    }

    conn->blank_line_offset = p - s - 1;
    return 0;
}

static int tws_ShouldParseTopPart(tws_conn_t *conn) {
    return conn->requestDictPtr == NULL && Tcl_DStringLength(&conn->ds) > 0 && tws_FoundBlankLine(conn);
}

static int tws_ShouldParseBottomPart(tws_conn_t *conn) {
    return conn->content_length > 0;
}

static int tws_ShouldReadMore(tws_conn_t *conn) {
    if (conn->content_length > 0) {
        int unprocessed = Tcl_DStringLength(&conn->ds) - conn->offset;
        return conn->content_length - unprocessed > 0;
    }
    return !tws_FoundBlankLine(conn);
}

static int
tws_ReturnError(Tcl_Interp *interp, tws_conn_t *conn, int status_code, const char *error_text, Tcl_Encoding encoding) {
    if (conn->error) {
        return TCL_OK;
    }

    Tcl_Obj *responseDictPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(responseDictPtr);
    Tcl_DictObjPut(interp, responseDictPtr, Tcl_NewStringObj("statusCode", -1), Tcl_NewIntObj(status_code));
    Tcl_DictObjPut(interp, responseDictPtr, Tcl_NewStringObj("body", -1), Tcl_NewStringObj(error_text, -1));
    if (TCL_OK != tws_ReturnConn(interp, conn, responseDictPtr, encoding)) {
        Tcl_DecrRefCount(responseDictPtr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(responseDictPtr);
    return TCL_OK;
}

static int tws_HandleRecv(tws_conn_t *conn) {
    DBG(fprintf(stderr, "HandleRecv: %s\n", conn->conn_handle));

    if (conn->ready) {
        DBG(fprintf(stderr, "HandleRecv - already ready\n"));
        return 1;
    }

    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(conn->dataKeyPtr, sizeof(tws_thread_data_t));

    if (tws_ShouldParseTopPart(conn)) {
        DBG(fprintf(stderr, "parse top part after deferring reqdictptr=%p\n", conn->requestDictPtr));
        // case when we have read as much as we could with deferring
        if (TCL_OK != tws_ParseTopPart(dataPtr->interp, conn)) {
            Tcl_Encoding encoding = Tcl_GetEncoding(dataPtr->interp, "utf-8");
            if (TCL_OK != tws_ReturnError(dataPtr->interp, conn, 400, "Bad Request", encoding)) {
                tws_CloseConn(conn, 1);
            }
            fprintf(stderr, "ParseTopPart failed (before rubicon): %s\n",
                    Tcl_GetString(Tcl_GetObjResult(dataPtr->interp)));
            return 1;
        }
    }

    // return 400 if we exceeded read timeout
    long long elapsed = current_time_in_millis() - conn->start_read_millis;
    if (elapsed > conn->accept_ctx->server->read_timeout_millis) {
        DBG(fprintf(stderr, "exceeded read timeout: %lld\n", elapsed));
        Tcl_Encoding encoding = Tcl_GetEncoding(dataPtr->interp, "utf-8");
        if (TCL_OK != tws_ReturnError(dataPtr->interp, conn, 400, "Bad Request", encoding)) {
            tws_CloseConn(conn, 1);
        }
        return 1;
    }

    int ret = TWS_DONE;
    if (tws_ShouldReadMore(conn)) {
        Tcl_Size remaining_unprocessed = Tcl_DStringLength(&conn->ds) - conn->offset;
        Tcl_Size bytes_to_read = conn->content_length == 0 ? 0 : conn->content_length - remaining_unprocessed;
        ret = conn->accept_ctx->read_fn(conn, &conn->ds, bytes_to_read);
    }

    if (TWS_AGAIN == ret) {
        if (tws_ShouldParseTopPart(conn) || tws_ShouldReadMore(conn)) {
            DBG(fprintf(stderr, "retry dslen=%zd offset=%zd reqdictptr=%p\n", Tcl_DStringLength(&conn->ds), conn->offset, conn->requestDictPtr));
            return 0;
        }
    } else if (TWS_ERROR == ret) {
        fprintf(stderr, "err\n");
        if (conn->requestDictPtr != NULL) {
            Tcl_DecrRefCount(conn->requestDictPtr);
            conn->requestDictPtr = NULL;
        }
        conn->error = 1;
        tws_CloseConn(conn, 2);
        return 1;
    } else if (TWS_DONE == ret && Tcl_DStringLength(&conn->ds) == 0) {
        // peer closed connection?
        tws_CloseConn(conn, 1);
        return 1;
    }

    DBG(fprintf(stderr, "rubicon conn->requestDictPtr=%p ret=%d dslen=%d content_length=%ld\n", conn->requestDictPtr, ret,
                Tcl_DStringLength(&conn->ds), conn->content_length));

    if (tws_ShouldParseTopPart(conn)) {
        // case when we have read as much as we could without deferring
        if (TCL_OK != tws_ParseTopPart(dataPtr->interp, conn)) {
            Tcl_Encoding encoding = Tcl_GetEncoding(dataPtr->interp, "utf-8");
            if (TCL_OK != tws_ReturnError(dataPtr->interp, conn, 400, "Bad Request", encoding)) {
                tws_CloseConn(conn, 1);
            }
            fprintf(stderr, "ParseTopPart failed (after rubicon): %s\n",
                    Tcl_GetString(Tcl_GetObjResult(dataPtr->interp)));
            return 1;
        }
    }

//    Tcl_Obj *req_dict_ptr = conn->requestDictPtr;
//    conn->requestDictPtr = NULL;

    if (tws_ShouldParseBottomPart(conn)) {
        if (TCL_OK != tws_ParseBottomPart(dataPtr->interp, conn, conn->requestDictPtr)) {
            fprintf(stderr, "ParseBottomPart failed: %s\n", Tcl_GetString(Tcl_GetObjResult(dataPtr->interp)));
            Tcl_DecrRefCount(conn->requestDictPtr);
            return 1;
        }
    } else {
        if (TCL_OK !=
            Tcl_DictObjPut(dataPtr->interp, conn->requestDictPtr, Tcl_NewStringObj("isBase64Encoded", -1), Tcl_NewBooleanObj(0))) {
            fprintf(stderr, "failed to write to dict");
            Tcl_DecrRefCount(conn->requestDictPtr);
            return 1;
        }
        if (TCL_OK !=
            Tcl_DictObjPut(dataPtr->interp, conn->requestDictPtr, Tcl_NewStringObj("body", -1), Tcl_NewStringObj("", -1))) {
            fprintf(stderr, "failed to write to dict");
            Tcl_DecrRefCount(conn->requestDictPtr);
            return 1;
        }
    }

    DBG(fprintf(stderr, "HandleRecv done\n"));

    conn->ready = 1;
//    conn->accept_ctx->handle_conn_fn = tws_HandleProcessing;
    return 1;
}

int tws_HandleSslHandshake(tws_conn_t *conn) {
    if (conn->handshaked) {
        DBG(fprintf(stderr, "HandleSslHandshake: already handshaked\n"));
        return 1;
    }
    ERR_clear_error();
    int rc = SSL_accept(conn->ssl);
    if (rc == 1) {
        DBG(fprintf(stderr, "HandleHandshake: success\n"));
        conn->handshaked = 1;
        conn->handle_conn_fn = tws_HandleRecv;
        return 1;
    }

    int err = SSL_get_error(conn->ssl, rc);
    if (err == SSL_ERROR_WANT_READ) {
        DBG(fprintf(stderr, "HandleHandshake: SSL_ERROR_WANT_READ\n"));
        return 0;
    } else if (err == SSL_ERROR_WANT_WRITE) {
        DBG(fprintf(stderr, "HandleHandshake: SSL_ERROR_WANT_WRITE\n"));
        return 0;
    } else if (err == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        fprintf(stderr, "peer closed connection in SSL handshake\n");
        conn->error = 1;
        tws_CloseConn(conn, 1);
        return 1;
    }
    fprintf(stderr, "SSL_accept <= 0 client: %d err=%s\n", conn->client, ssl_errors[err]);
    conn->error = 1;
    tws_CloseConn(conn, 1);
    ERR_print_errors_fp(stderr);
    return 1;
}

static int tws_HandleProcessEventInThread(Tcl_Event *evPtr, int flags) {
    tws_event_t *connEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) connEvPtr->clientData;
    if (conn->ready || conn->shutdown) {
        DBG(fprintf(stderr, "HandleProcessEventInThread: ready: %d shutdown: %d\n", conn->ready, conn->shutdown));
        return 1;
    }

    DBG(fprintf(stderr, "HandleProcessEventInThread: %s\n", conn->conn_handle));
    conn->handle_conn_fn(conn);
    DBG(fprintf(stderr, "HandleProcessEventInThread: ready=%d\n", conn->ready));

    // DoRouting closes the connection when done processing
    // so, we keep the state of the ready flag to avoid processing it again
    int ready = conn->ready;
    if (ready) {
        tws_HandleProcessing(conn);
    } else {
        Tcl_ThreadAlert(conn->threadId);
    }
    return ready;
}

static void tws_QueueProcessEvent(tws_conn_t *conn) {
    DBG(fprintf(stderr, "ThreadQueueProcessEvent - threadId: %p\n", conn->threadId));
    tws_event_t *connEvPtr = (tws_event_t *) Tcl_Alloc(sizeof(tws_event_t));
    connEvPtr->proc = tws_HandleProcessEventInThread;
    connEvPtr->nextPtr = NULL;
    connEvPtr->clientData = (ClientData *) conn;
    Tcl_QueueEvent((Tcl_Event *) connEvPtr, TCL_QUEUE_TAIL);
     Tcl_ThreadAlert(conn->threadId);
    DBG(fprintf(stderr, "ThreadQueueProcessEvent done - threadId: %p\n", conn->threadId));
}

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
static int tws_HandleConnEventInThread(Tcl_Event *evPtr, int flags) {
    tws_event_t *connEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) connEvPtr->clientData;

    DBG(fprintf(stderr, "current thread: %p conn->threadId: %p\n", Tcl_GetCurrentThread(), conn->threadId));

    tws_AddConnToThreadList(conn);
    tws_QueueProcessEvent(conn);
    return 1;
}

// this is called from the main thread
// to queue the event in the thread that the connection will be processed
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

static int tws_HandleKeepaliveEventInThread(Tcl_Event *evPtr, int flags) {
    tws_event_t *connEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) connEvPtr->clientData;

    fprintf(stderr, "current thread: %p conn->threadId: %p\n", Tcl_GetCurrentThread(), conn->threadId);
    conn->start_read_millis = current_time_in_millis();
    conn->latest_millis = conn->start_read_millis;

    tws_QueueProcessEvent(conn);

    return 1;
}

static void tws_ThreadQueueKeepaliveEvent(tws_conn_t *conn) {
    DBG(fprintf(stderr, "ThreadQueueKeepaliveEvent - threadId: %p\n", conn->threadId));
    tws_event_t *connEvPtr = (tws_event_t *) Tcl_Alloc(sizeof(tws_event_t));
    connEvPtr->proc = tws_HandleKeepaliveEventInThread;
    connEvPtr->nextPtr = NULL;
    connEvPtr->clientData = (ClientData *) conn;
    Tcl_ThreadQueueEvent(conn->threadId, (Tcl_Event *) connEvPtr, TCL_QUEUE_TAIL);
    Tcl_ThreadAlert(conn->threadId);
    DBG(fprintf(stderr, "ThreadQueueKeepaliveEvent done - threadId: %p\n", conn->threadId));
}
#endif

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

static int tws_AddConnToThreadList(tws_conn_t *conn) {

    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));
    Tcl_MutexLock(&tws_Thread_Mutex);

    // prefer to refuse connection if we are over the limit
    // this is to cap memory usage
    int thread_limit = conn->accept_ctx->server->thread_max_concurrent_conns;
    if (thread_limit > 0 && dataPtr->numConns >= thread_limit) {
        shutdown(conn->client, SHUT_RDWR);
        close(conn->client);
        SSL_free(conn->ssl);
        Tcl_Free((char *) conn);
        Tcl_MutexUnlock(&tws_Thread_Mutex);
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

    DBG(fprintf(stderr, "AddConnToThreatList - numConns: %d FD_SETSIZE: %d thread_limit: %d\n", dataPtr->numConns, FD_SETSIZE, thread_limit));

    Tcl_MutexUnlock(&tws_Thread_Mutex);

    return 1;
}

void tws_AcceptConn(void *data, int mask) {
    DBG(fprintf(stderr, "-------------------tws_AcceptConn\n"));

    tws_accept_ctx_t *accept_ctx = (tws_accept_ctx_t *) data;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    struct timespec timeout;
    timeout.tv_sec = 1;  // 0 seconds
    timeout.tv_nsec = 1000; // 1000 nanoseconds

//    struct kevent events[MAX_EVENTS];
//    int nfds = kevent(accept_ctx->epoll_fd, NULL, 0, events, MAX_EVENTS, &timeout);
//    if (nfds == -1) {
//        fprintf(stderr, "kevent failed");
//        return;
//    }
#else
    struct epoll_event events[MAX_EVENTS];
    int nfds = epoll_wait(accept_ctx->epoll_fd, events, MAX_EVENTS, 0);
    if (nfds == -1) {
        fprintf(stderr, "epoll_wait failed");
        return;
    }
#endif

//    if (nfds==0) {
//        fprintf(stderr, "-------------------tws_AcceptConn, nfds: %d\n", nfds);
//    }

//    for (int i = 0; i < nfds; i++) {
//#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
//        if (events[i].ident == accept_ctx->server_fd) {
//#else
//        if (events[i].data.fd == accept_ctx->server_fd) {
//#endif
            // new incoming connection

            struct sockaddr_in6 client_addr;
            unsigned int len = sizeof(client_addr);
            int client = accept(accept_ctx->server_fd, (struct sockaddr *) &client_addr, &len);
            DBG(fprintf(stderr, "client: %d\n", client));
            if (client < 0) {
                fprintf(stderr, "Unable to accept\n");
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
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
            tws_ThreadQueueConnEvent(conn);
#else
            tws_AddConnToThreadList(conn);
            tws_QueueProcessEvent(conn);
#endif
//        } else {
//             data available on an existing connection
//             we do not have any as each thread has its own epoll instance
//        }

//    }
}

Tcl_ThreadCreateType tws_HandleConnThread(ClientData clientData) {

    tws_thread_ctrl_t *ctrl = (tws_thread_ctrl_t *) clientData;

    DBG(Tcl_ThreadId threadId = Tcl_GetCurrentThread());
//    static Tcl_Mutex mutex;
    // Get a pointer to the thread data for the current thread
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));
    // Create a new interp for this thread and store it in the thread data
    dataPtr->interp = Tcl_CreateInterp();
    dataPtr->cmdPtr = Tcl_DuplicateObj(ctrl->server->cmdPtr);
//    &tws_Thread_Mutex = &mutex;
    dataPtr->server = ctrl->server;
    dataPtr->thread_index = ctrl->thread_index;
    dataPtr->numRequests = 0;
    dataPtr->thread_pivot = dataPtr->thread_index * (ctrl->server->garbage_collection_cleanup_threshold / ctrl->server->num_threads);
    dataPtr->numConns = 0;
    dataPtr->firstConnPtr = NULL;
    dataPtr->lastConnPtr = NULL;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    dataPtr->epoll_fd = kqueue();
#else
    dataPtr->epoll_fd = epoll_create1(0);
#endif
    tws_SetBlockingMode(dataPtr->epoll_fd, TWS_MODE_NONBLOCKING);

    Tcl_IncrRefCount(dataPtr->cmdPtr);

    DBG(fprintf(stderr, "created interp=%p\n", dataPtr->interp));

    Tcl_InitMemory(dataPtr->interp);
    if (TCL_OK != Tcl_Init(dataPtr->interp)) {
        DBG(fprintf(stderr, "error initializing Tcl\n"));
        Tcl_FinalizeThread();
        Tcl_ExitThread(TCL_ERROR);
        TCL_THREAD_CREATE_RETURN;
    }

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#else
    int server_fd;
    int epoll_fd;
    if (TCL_OK != create_socket(dataPtr->interp, ctrl->server, ctrl->host, ctrl->port, &server_fd) || server_fd < 0) {
        fprintf(stderr, "failed to create socket on thread\n");
        Tcl_FinalizeThread();
        Tcl_ExitThread(TCL_ERROR);
        TCL_THREAD_CREATE_RETURN;
    }

    if (TCL_OK != create_epoll_fd(dataPtr->interp, server_fd, &epoll_fd) || epoll_fd < 0) {
        fprintf(stderr, "failed to create epoll fd on thread\n");
        Tcl_FinalizeThread();
        Tcl_ExitThread(TCL_ERROR);
        TCL_THREAD_CREATE_RETURN;
    }

    DBG(fprintf(stderr, "port: %s - created listening socket on thread: %d\n", ctrl->port, ctrl->thread_index));
#endif

    tws_accept_ctx_t *accept_ctx = (tws_accept_ctx_t *) Tcl_Alloc(sizeof(tws_accept_ctx_t));

    if (ctrl->option_http) {
        accept_ctx->read_fn = tws_ReadHttpConnAsync;
        accept_ctx->write_fn = tws_WriteHttpConnAsync;
        accept_ctx->handle_conn_fn = tws_HandleRecv;
    } else {

        accept_ctx->read_fn = tws_ReadSslConnAsync;
        accept_ctx->write_fn = tws_WriteSslConnAsync;
        accept_ctx->handle_conn_fn = tws_HandleSslHandshake;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#else
        // it is an https server, so we need to create an SSL_CTX
        if (TCL_OK != tws_CreateSslContext(dataPtr->interp, &accept_ctx->sslCtx)) {
            Tcl_Free((char *) accept_ctx);
            Tcl_FinalizeThread();
            Tcl_ExitThread(TCL_ERROR);
            TCL_THREAD_CREATE_RETURN;
        }
        SSL_CTX_set_client_hello_cb(accept_ctx->sslCtx, tws_ClientHelloCallback, NULL);
#endif
    }

    accept_ctx->option_http = ctrl->option_http;
    accept_ctx->port = atoi(ctrl->port);
    accept_ctx->interp = dataPtr->interp;
    accept_ctx->server = ctrl->server;
// todo:    accept_ctx->num_threads = ctrl->option_num_threads;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#else
    accept_ctx->server_fd = server_fd;
    accept_ctx->epoll_fd = epoll_fd;
    Tcl_CreateFileHandler(epoll_fd, TCL_READABLE, tws_AcceptConn, accept_ctx);

#endif

    // create a file handler for the epoll fd for this thread
    Tcl_CreateFileHandler(dataPtr->epoll_fd, TCL_READABLE, tws_KeepaliveConnHandler, NULL);

    if (TCL_OK != Tcl_EvalObj(dataPtr->interp, ctrl->server->scriptPtr)) {
        fprintf(stderr, "error evaluating init script\n");
        fprintf(stderr, "error=%s\n", Tcl_GetString(Tcl_GetObjResult(dataPtr->interp)));
        fprintf(stderr, "%s\n", Tcl_GetVar2(dataPtr->interp, "::errorInfo", NULL, TCL_GLOBAL_ONLY));
        Tcl_FinalizeThread();
        Tcl_ExitThread(TCL_ERROR);
        TCL_THREAD_CREATE_RETURN;
    }

    // notify the main thread that we are done initializing
    Tcl_ConditionNotify(&ctrl->condWait);

    DBG(fprintf(stderr, "HandleConnThread: in (%p)\n", Tcl_GetCurrentThread()));
    Tcl_Time block_time = {0, 10000};
//    Tcl_SetMaxBlockTime(&block_time);
    while (1) {
//        fprintf(stderr, "HandleConnThread: in conn loop\n");
        Tcl_DoOneEvent(TCL_ALL_EVENTS);
//        Tcl_DoOneEvent(TCL_DONT_WAIT);
//        Tcl_WaitForEvent(&block_time);
    }
    Tcl_Free(accept_ctx);
    Tcl_FinalizeThread();
    Tcl_ExitThread(TCL_OK);
    TCL_THREAD_CREATE_RETURN;
}

static void tws_KeepaliveConnHandler(void *data, int mask) {

        DBG(fprintf(stderr, "KeepaliveConnHandler\n"));


    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(&dataKey, sizeof(tws_thread_data_t));

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    struct timespec timeout;
    timeout.tv_sec = 0;  // 0 seconds
    timeout.tv_nsec = 1000; // 1000 nanoseconds

    struct kevent events[MAX_EVENTS];
    int nfds = kevent(dataPtr->epoll_fd, NULL, 0, events, MAX_EVENTS, &timeout);
    if (nfds == -1) {
        fprintf(stderr, "KeepaliveConnHandler: kevent failed");
        return;
    }
#else
    struct epoll_event events[MAX_EVENTS];
    int nfds = epoll_wait(dataPtr->epoll_fd, events, MAX_EVENTS, 0);
    if (nfds == -1) {
        fprintf(stderr, "KeepaliveConnHandler: epoll_wait failed");
        return;
    }
#endif

    DBG(fprintf(stderr, "KeepaliveConnHandler - nfds: %d\n", nfds));

    for (int i = 0; i < nfds; i++) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        tws_conn_t *conn = (tws_conn_t *) events[i].udata;
        tws_ThreadQueueKeepaliveEvent(conn);
#else
        tws_conn_t *conn = (tws_conn_t *) events[i].data.ptr;
        DBG(fprintf(stderr, "KeepaliveConnHandler - keepalive client: %d %s\n", conn->client, conn->conn_handle));
        conn->start_read_millis = current_time_in_millis();
        conn->latest_millis = conn->start_read_millis;

        tws_QueueProcessEvent(conn);
#endif
    }

}

int tws_Listen(Tcl_Interp *interp, tws_server_t *server, int option_http, int option_num_threads, const char *host, const char *port) {

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    int server_fd;
    if (TCL_OK != create_socket(interp, server, host, port, &server_fd) || server_fd < 0) {
        fprintf(stderr, "failed to create socket on main thread\n");
        SetResult("Failed to create server socket");
        return TCL_ERROR;
    }

    int epoll_fd;
    if (TCL_OK != create_epoll_fd(interp, server_fd, &epoll_fd) || epoll_fd < 0) {
        fprintf(stderr, "failed to create epoll fd on main thread\n");
        SetResult("Failed to create epoll fd");
        return TCL_ERROR;
    }

    tws_accept_ctx_t *accept_ctx = (tws_accept_ctx_t *) Tcl_Alloc(sizeof(tws_accept_ctx_t));

    if (option_http) {
        accept_ctx->read_fn = tws_ReadHttpConnAsync;
        accept_ctx->write_fn = tws_WriteHttpConnAsync;
        accept_ctx->handle_conn_fn = tws_HandleRecv;
    } else {
        accept_ctx->read_fn = tws_ReadSslConnAsync;
        accept_ctx->write_fn = tws_WriteSslConnAsync;
        accept_ctx->handle_conn_fn = tws_HandleSslHandshake;

        if (TCL_OK != tws_CreateSslContext(interp, &accept_ctx->sslCtx)) {
            Tcl_Free((char *) accept_ctx);
            SetResult("Failed to create SSL context");
            return TCL_ERROR;
        }
        SSL_CTX_set_client_hello_cb(accept_ctx->sslCtx, tws_ClientHelloCallback, NULL);

    }

    accept_ctx->option_http = option_http;
    accept_ctx->port = atoi(port);
    accept_ctx->interp = interp;
    accept_ctx->server = server;
    accept_ctx->num_threads = option_num_threads;

    accept_ctx->server_fd = server_fd;
    accept_ctx->epoll_fd = epoll_fd;

    Tcl_CreateFileHandler(server_fd, TCL_READABLE, tws_AcceptConn, accept_ctx);

    DBG(fprintf(stderr, "port: %s - created listening socket (%d) on main thread\n", port, server_fd));

    accept_ctx->conn_thread_ids = (Tcl_ThreadId *) Tcl_Alloc(option_num_threads * sizeof(Tcl_ThreadId));
#else
#endif

    for (int i = 0; i < option_num_threads; i++) {
        Tcl_MutexLock(&tws_Thread_Mutex);
        Tcl_ThreadId id;
        tws_thread_ctrl_t ctrl;
        ctrl.condWait = NULL;
        ctrl.server = server;
        ctrl.thread_index = i;
        ctrl.host = host;
        ctrl.port = port;
        ctrl.option_http = option_http;
        if (TCL_OK !=
            Tcl_CreateThread(&id, tws_HandleConnThread, &ctrl, server->thread_stacksize, TCL_THREAD_NOFLAGS)) {
            Tcl_MutexUnlock(&tws_Thread_Mutex);
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
            Tcl_Free((char *) accept_ctx);
#endif
            SetResult("Unable to create thread");
            return TCL_ERROR;
        }
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        DBG(fprintf(stderr, "Listen - created thread: %p\n", id));
        accept_ctx->conn_thread_ids[i] = id;
        DBG(fprintf(stderr, "Listen - created thread: %p (check)\n", accept_ctx->conn_thread_ids[i]));
#endif

        // Wait for the thread to start because it is using something on our stack!
        Tcl_ConditionWait(&ctrl.condWait, &tws_Thread_Mutex, NULL);
        Tcl_MutexUnlock(&tws_Thread_Mutex);
        Tcl_ConditionFinalize(&ctrl.condWait);
        DBG(fprintf(stderr, "Listen - created thread: %p\n", id));
    }

    return TCL_OK;
}
