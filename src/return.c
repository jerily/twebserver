/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include <unistd.h>
#include "return.h"
#include "base64.h"

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/event.h>
#include <assert.h>

#else

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <assert.h>

#endif

#define MAX_EVENTS 100
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define MAX_BUFFER_SIZE 1024
#endif

#define MAX_CHUNK_SIZE 10485760

void tws_QueueCreateFileHandlerEvent(tws_conn_t *conn);
void tws_QueueCleanupEvent();
static int tws_HandleCreateFileHandlerEventInThread(Tcl_Event *evPtr, int flags);
static void tws_CreateFileHandler(int fd, ClientData clientData);
static void tws_ShutdownConn(tws_conn_t *conn);
static int tws_HandleCleanupEventInThread(Tcl_Event *evPtr, int flags);

static void tws_FreeConnWithThreadData(tws_conn_t *conn, tws_thread_data_t *dataPtr) {
    assert(valid_conn_handle(conn));

    DBG(fprintf(stderr, "FreeConnWithThreadData - dataKey: %p thread: %p - client: %d - num_conns: %d\n", tws_GetThreadDataKey(), Tcl_GetCurrentThread(), conn->client, dataPtr->num_conns));

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

    if (!conn->accept_ctx->option_http) {
        SSL_free(conn->ssl);
    }
    Tcl_DStringFree(&conn->inout_ds);
    Tcl_DStringFree(&conn->parse_ds);
    Tcl_Free((char *) conn);

    dataPtr->num_conns--;
}

static void tws_FreeConn(tws_conn_t *conn) {
    Tcl_MutexLock(tws_GetThreadMutex());
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(tws_GetThreadDataKey(), sizeof(tws_thread_data_t));
    tws_FreeConnWithThreadData(conn, dataPtr);
    Tcl_MutexUnlock(tws_GetThreadMutex());
}

int tws_CleanupConnections() {
    Tcl_ThreadId currentThreadId = Tcl_GetCurrentThread();
    DBG(fprintf(stderr, "CleanupConnections currentThreadId=%p\n", currentThreadId));

    long long milliseconds = current_time_in_millis();

    int count = 0;
    int count_mark_for_deletion = 0;

    Tcl_MutexLock(tws_GetThreadMutex());
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(tws_GetThreadDataKey(), sizeof(tws_thread_data_t));
    tws_conn_t *curr_conn = dataPtr->firstConnPtr;
    tws_conn_t *next_conn = NULL;
    while (curr_conn != NULL) {

        next_conn = curr_conn->nextPtr;

        if (curr_conn->todelete) {
            DBG(fprintf(stderr, "CleanupConnections - deleting conn - client: %d\n", curr_conn->client));

            tws_FreeConnWithThreadData(curr_conn, dataPtr);

            DBG(fprintf(stderr, "CleanupConnections - deleted conn\n"));
        } else {
            long long elapsed = milliseconds - curr_conn->latest_millis;
            if (elapsed > curr_conn->accept_ctx->server->conn_timeout_millis) {
                if (tws_UnregisterConnName(curr_conn->handle)) {
                    DBG(fprintf(stderr, "CleanupConnections - mark connection for deletion\n"));
                    tws_ShutdownConn(curr_conn);
                    curr_conn->todelete = 1;
                    count_mark_for_deletion++;
                }
            }
        }
        count++;

        curr_conn = next_conn;
    }
    Tcl_MutexUnlock(tws_GetThreadMutex());

    DBG(fprintf(stderr, "reviewed count: %d marked_for_deletion: %d\n", count, count_mark_for_deletion));

    return 1;
}

static int tws_HandleCleanupEventInThread(Tcl_Event *evPtr, int flags) {
    UNUSED(evPtr);
    UNUSED(flags);

    return tws_CleanupConnections();
}

static void tws_CreateFileHandler(int fd, ClientData clientData) {
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(tws_GetThreadDataKey(), sizeof(tws_thread_data_t));

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
    UNUSED(flags);

    DBG(fprintf(stderr, "CreateFileHandlerForKeepaliveConn\n"));
    tws_event_t *keepaliveEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) keepaliveEvPtr->clientData;
    DBG(fprintf(stderr, "CreateFileHandlerForKeepaliveConn conn=%p client=%d\n", conn, conn->client));
    tws_CreateFileHandler(conn->client, conn);

    return 1;
}

void tws_QueueCleanupEvent() {
    Tcl_ThreadId currentThreadId = Tcl_GetCurrentThread();
    DBG(fprintf(stderr, "QueueCleanupEvent: %p\n", currentThreadId));
    Tcl_Event *evPtr = (Tcl_Event *) Tcl_Alloc(sizeof(Tcl_Event));
    evPtr->proc = tws_HandleCleanupEventInThread;
    evPtr->nextPtr = NULL;
    Tcl_QueueEvent((Tcl_Event *) evPtr, TCL_QUEUE_TAIL);
    Tcl_ThreadAlert(currentThreadId);
}

static int tws_HandleFreeConnEventInThread(Tcl_Event *evPtr, int flags) {
    UNUSED(flags);

    tws_event_t *connEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) connEvPtr->clientData;
    tws_FreeConn(conn);
    return 1;
}

void tws_QueueFreeConnEvent(tws_conn_t *conn) {
    Tcl_ThreadId currentThreadId = Tcl_GetCurrentThread();
    DBG(fprintf(stderr, "QueueFreeConnEvent: %p\n", currentThreadId));
    tws_event_t *connEvPtr = (tws_event_t *) Tcl_Alloc(sizeof(tws_event_t));
    connEvPtr->proc = tws_HandleFreeConnEventInThread;
    connEvPtr->nextPtr = NULL;
    connEvPtr->clientData = (ClientData *) conn;
    Tcl_QueueEvent((Tcl_Event *) connEvPtr, TCL_QUEUE_TAIL);
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

static void tws_DeleteFileHandler(int fd) {
    DBG(fprintf(stderr, "DeleteFileHandler client: %d\n", fd));

    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(tws_GetThreadDataKey(), sizeof(tws_thread_data_t));

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

static void tws_ShutdownConn(tws_conn_t *conn) {
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
            if (errno != ENOTCONN) {
                fprintf(stderr, "failed to shutdown client: %d error=%d\n", conn->client, errno);
            }
        }
    }

    if (close(conn->client)) {
        fprintf(stderr, "close failed\n");
    }

    DBG(fprintf(stderr, "done shutdown\n"));
}

int tws_CloseConn(tws_conn_t *conn, int force) {
    assert(valid_conn_handle(conn));

    if (conn->shutdown) {
        return TCL_OK;
    }

    DBG(fprintf(stderr, "CloseConn - client: %d force: %d keepalive: %d handler: %d\n", conn->client, force,
                conn->keepalive, conn->created_file_handler_p));

    Tcl_DStringSetLength(&conn->inout_ds, 0);
    Tcl_DStringSetLength(&conn->parse_ds, 0);
    conn->top_part_offset = 0;
    conn->write_offset = 0;
    conn->blank_line_offset = 0;
    conn->content_length = 0;
    if (conn->req_dict_ptr) {
        Tcl_DecrRefCount(conn->req_dict_ptr);
    }
    conn->req_dict_ptr = NULL;
//    conn->handle_conn_fn = NULL;
    conn->shutdown = 0;
    conn->ready = 0;
    conn->inprogress = 0;
//    conn->handshaked = 0;
    for (Tcl_Size i = 0; i < conn->n_chunks; i++) {
        Tcl_DStringFree(&conn->chunks_ds[i]);
    }
    Tcl_Free(conn->chunks_ds);
    conn->n_chunks = 0;
    conn->chunk_offset = 0;


    if (force) {
        if (tws_UnregisterConnName(conn->handle)) {
            tws_ShutdownConn(conn);
            tws_QueueFreeConnEvent(conn);
        }
    } else {
        if (!conn->keepalive) {
            if (tws_UnregisterConnName(conn->handle)) {
                tws_ShutdownConn(conn);
                tws_QueueFreeConnEvent(conn);
            }
        } else {
            if (!conn->created_file_handler_p) {
                conn->created_file_handler_p = 1;
                // notify the event loop to keep the connection alive
                tws_QueueCreateFileHandlerEvent(conn);
            }
        }
    }

    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(tws_GetThreadDataKey(), sizeof(tws_thread_data_t));
    dataPtr->num_requests = (dataPtr->num_requests + 1) % INT_MAX;
    tws_server_t *server = conn->accept_ctx->server;
    // make sure that garbage collection does not start the same time on all threads
    if (dataPtr->num_requests % server->garbage_collection_cleanup_threshold == dataPtr->thread_pivot) {
        tws_QueueCleanupEvent();
    }

    return TCL_OK;
}
static int tws_HandleWrite(tws_conn_t *conn) {
    assert(valid_conn_handle(conn));

    Tcl_DString *ds_ptr = &conn->inout_ds;
    if (conn->chunk_offset > 0) {
        ds_ptr = &conn->chunks_ds[conn->chunk_offset - 1];
    }

    DBG(fprintf(stderr, "chunk_offset: %ld n_chunks: %ld write_offset: %ld\n", conn->chunk_offset, conn->n_chunks, conn->write_offset));

    Tcl_Size reply_length = Tcl_DStringLength(ds_ptr);
    const char *reply = Tcl_DStringValue(ds_ptr);

    int rc = conn->accept_ctx->write_fn(conn, reply + conn->write_offset, reply_length - conn->write_offset);

    if (rc == TWS_AGAIN) {
        DBG(fprintf(stderr, "TWS_AGAIN write_offset: %ld reply_length: %ld n_chunks: %ld\n", conn->write_offset, reply_length, conn->n_chunks));
        return 0;
    } else if (rc == TWS_ERROR) {
        DBG(fprintf(stderr, "TWS_ERROR\n"));
        conn->error = 1;
        tws_CloseConn(conn, 1);
        return 1;
    }

    DBG(fprintf(stderr, "TWS_DONE write_offset: %ld reply_length: %ld n_chunks: %ld\n", conn->write_offset, reply_length, conn->n_chunks));

    if (conn->n_chunks > 0) {
        conn->write_offset = 0;
        conn->chunk_offset++;
        if (conn->chunk_offset <= conn->n_chunks) {
            return 0;
        }
    }

    // TWS_DONE
    tws_CloseConn(conn, 0);

    DBG(fprintf(stderr, "------------done\n"));
    return 1;
}

static int tws_HandleWriteEventInThread(Tcl_Event *evPtr, int flags) {
    UNUSED(flags);

    tws_event_t *connEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) connEvPtr->clientData;

    assert(valid_conn_handle(conn));

    DBG(fprintf(stderr, "HandleWriteEventInThread: %s\n", conn->handle));

    int result = tws_HandleWrite(conn);
    Tcl_ThreadAlert(conn->threadId);
    return result;
}

static void tws_QueueWriteEvent(tws_conn_t *conn) {
    assert(valid_conn_handle(conn));

    DBG(fprintf(stderr, "QueueWriteEvent - threadId: %p conn: %s\n", conn->threadId, conn->handle));
    conn->write_offset = 0;
    tws_event_t *connEvPtr = (tws_event_t *) Tcl_Alloc(sizeof(tws_event_t));
    connEvPtr->proc = tws_HandleWriteEventInThread;
    connEvPtr->nextPtr = NULL;
    connEvPtr->clientData = (ClientData *) conn;
    Tcl_QueueEvent((Tcl_Event *) connEvPtr, TCL_QUEUE_TAIL);
    Tcl_ThreadAlert(conn->threadId);
    DBG(fprintf(stderr, "QueueWriteEvent done - threadId: %p\n", conn->threadId));

}

int tws_ReturnConn(Tcl_Interp *interp, tws_conn_t *conn, Tcl_Obj *const responseDictPtr) {
    assert(valid_conn_handle(conn));

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
    if (TCL_OK != Tcl_DictObjGet(interp, responseDictPtr, headersKeyPtr, &headersPtr)) {
        Tcl_DecrRefCount(headersKeyPtr);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(headersKeyPtr);

    Tcl_Obj *multiValueHeadersPtr;
    Tcl_Obj *multiValueHeadersKeyPtr = Tcl_NewStringObj("multiValueHeaders", -1);
    Tcl_IncrRefCount(multiValueHeadersKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, responseDictPtr, multiValueHeadersKeyPtr, &multiValueHeadersPtr)) {
        Tcl_DecrRefCount(multiValueHeadersKeyPtr);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(multiValueHeadersKeyPtr);

    Tcl_Obj *bodyPtr;
    Tcl_Obj *bodyKeyPtr = Tcl_NewStringObj("body", -1);
    Tcl_IncrRefCount(bodyKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, responseDictPtr, bodyKeyPtr, &bodyPtr)) {
        Tcl_DecrRefCount(bodyKeyPtr);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(bodyKeyPtr);

    if (!bodyPtr) {
        SetResult("body not found");
        return TCL_ERROR;
    }

    Tcl_Obj *isBase64EncodedPtr;
    Tcl_Obj *isBase64EncodedKeyPtr = Tcl_NewStringObj("isBase64Encoded", -1);
    Tcl_IncrRefCount(isBase64EncodedKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, responseDictPtr, isBase64EncodedKeyPtr, &isBase64EncodedPtr)) {
        Tcl_DecrRefCount(isBase64EncodedKeyPtr);
        SetResult("error reading from dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(isBase64EncodedKeyPtr);

    Tcl_DStringSetLength(&conn->inout_ds, 0);
    Tcl_DStringAppend(&conn->inout_ds, "HTTP/1.1 ", 9);

    Tcl_Size status_code_length;
    const char *status_code = Tcl_GetStringFromObj(statusCodePtr, &status_code_length);
    Tcl_DStringAppend(&conn->inout_ds, status_code, status_code_length);

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
                if (TCL_OK != Tcl_DictObjGet(interp, multiValueHeadersPtr, keyPtr, &listPtr)) {
                    SetResult("error reading from dict");
                    return TCL_ERROR;
                }
                if (listPtr) {
                    continue;
                }
            }
            Tcl_DStringAppend(&conn->inout_ds, "\r\n", 2);
            Tcl_Size key_length;
            const char *key = Tcl_GetStringFromObj(keyPtr, &key_length);
            Tcl_DStringAppend(&conn->inout_ds, key, key_length);
            Tcl_DStringAppend(&conn->inout_ds, ": ", 2);
            Tcl_Size value_length;
            const char *value = Tcl_GetStringFromObj(valuePtr, &value_length);
            Tcl_DStringAppend(&conn->inout_ds, value, value_length);
        }
        Tcl_DictObjDone(&headersSearch);
    }

    if (multiValueHeadersPtr) {
        // write each "header" from the "multiValueHeaders" dictionary to the ssl connection
        Tcl_DictSearch mvHeadersSearch;
        for (Tcl_DictObjFirst(interp, multiValueHeadersPtr, &mvHeadersSearch, &keyPtr, &valuePtr, &done);
             !done;
             Tcl_DictObjNext(&mvHeadersSearch, &keyPtr, &valuePtr, &done)) {

            Tcl_DStringAppend(&conn->inout_ds, "\r\n", 2);
            Tcl_Size key_length;
            const char *key = Tcl_GetStringFromObj(keyPtr, &key_length);
            Tcl_DStringAppend(&conn->inout_ds, key, key_length);
            Tcl_DStringAppend(&conn->inout_ds, ": ", 2);

            // "valuePtr" is a list, iterate over its elements
            Tcl_Size list_length;
            Tcl_ListObjLength(interp, valuePtr, &list_length);
            for (int i = 0; i < list_length; i++) {
                Tcl_Obj *elemPtr;
                Tcl_ListObjIndex(interp, valuePtr, i, &elemPtr);
                Tcl_Size value_length;
                const char *value = Tcl_GetStringFromObj(elemPtr, &value_length);
                Tcl_DStringAppend(&conn->inout_ds, value, value_length);
                if (i < value_length - 1) {
                    Tcl_DStringAppend(&conn->inout_ds, ", ", 2);
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
    if (isBase64Encoded) {

        Tcl_Size b64_body_length;
        const char *b64_body = Tcl_GetStringFromObj(bodyPtr, &b64_body_length);
        if (b64_body_length > 0) {
            body = Tcl_Alloc(3 * b64_body_length / 4 + 2);
            body_alloc = 1;
            if (base64_decode(b64_body, b64_body_length, body, &body_length)) {
                Tcl_Free(body);
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
            if (body_alloc) {
                Tcl_Free(body);
            }
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
        Tcl_DStringAppend(&conn->inout_ds, "\r\n", 2);
        Tcl_DStringAppend(&conn->inout_ds, "Content-Encoding: gzip", 22);
    }

    Tcl_Obj *compressed = NULL;
    if (gzip_p) {

        Tcl_Obj *baObj = Tcl_NewByteArrayObj(body, body_length);
        Tcl_IncrRefCount(baObj);
        if (Tcl_ZlibDeflate(interp, TCL_ZLIB_FORMAT_GZIP, baObj,
                            TCL_ZLIB_COMPRESS_FAST, NULL)) {
            Tcl_DecrRefCount(baObj);
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
    Tcl_Size content_length_str_len;
    const char *content_length_str = Tcl_GetStringFromObj(contentLengthPtr, &content_length_str_len);
    Tcl_DStringAppend(&conn->inout_ds, "\r\n", 2);
    Tcl_DStringAppend(&conn->inout_ds, "Content-Length: ", 16);
    Tcl_DStringAppend(&conn->inout_ds, content_length_str, content_length_str_len);

    if (body_length < MAX_CHUNK_SIZE) {
        Tcl_DStringAppend(&conn->inout_ds, "\r\n\r\n", 4);
        if (body_length > 0) {
            Tcl_DStringAppend(&conn->inout_ds, body, body_length);
        }
    } else {
        Tcl_DStringAppend(&conn->inout_ds, "\r\n", 2);
        Tcl_DStringAppend(&conn->inout_ds, "Transfer-Encoding: chunked", 26);
        Tcl_DStringAppend(&conn->inout_ds, "\r\n\r\n", 4);

        // chunk the body
        // it should be:
        // 1. chunk size in hex
        // 2. \r\n
        // 3. chunk data
        // 4. \r\n
        // 5. repeat 1-4 until all data is sent
        // 6. 0
        // 7. \r\n
        // 8. \r\n

        conn->n_chunks = (body_length / MAX_CHUNK_SIZE) + 1;
        DBG(fprintf(stderr, "n_chunks: %ld\n", conn->n_chunks));
        conn->chunks_ds = (Tcl_DString *) Tcl_Alloc(sizeof(Tcl_DString) * conn->n_chunks);
        Tcl_Size chunk_index = 0;
        for (Tcl_Size i = 0; i < body_length; i += MAX_CHUNK_SIZE) {
            Tcl_DStringInit(&conn->chunks_ds[chunk_index]);
            Tcl_Size chunk_size = MIN(body_length - i, MAX_CHUNK_SIZE);
            char chunk_size_str[16];
            snprintf(chunk_size_str, 16, "%lx", chunk_size);
            Tcl_DStringAppend(&conn->chunks_ds[chunk_index], chunk_size_str, strlen(chunk_size_str));
            Tcl_DStringAppend(&conn->chunks_ds[chunk_index], "\r\n", 2);
            Tcl_DStringAppend(&conn->chunks_ds[chunk_index], body + i, chunk_size);
            Tcl_DStringAppend(&conn->chunks_ds[chunk_index], "\r\n", 2);
            chunk_index++;
        }
        Tcl_DStringAppend(&conn->chunks_ds[conn->n_chunks - 1], "0\r\n\r\n", -1);
    }
    Tcl_DecrRefCount(contentLengthPtr);

    if (compressed != NULL) {
        Tcl_DecrRefCount(compressed);
    } else if (body_alloc) {
        // if "body" was allocated, free it
        // if we used compression, "body" was freed above
        Tcl_Free((char *) body);
    }

    tws_QueueWriteEvent(conn);

    return TCL_OK;
}


int
tws_ReturnError(Tcl_Interp *interp, tws_conn_t *conn, int status_code, const char *error_text) {
    assert(valid_conn_handle(conn));

    DBG(fprintf(stderr, "ReturnError: %d %s\n", conn->client, conn->handle));
    if (conn->error) {
        return TCL_ERROR;
    }

    // to stop HandleProcessEventInThread from calling anything
    conn->ready = 1;
    conn->inprogress = 1;

    Tcl_Obj *responseDictPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(responseDictPtr);
    if (TCL_OK != Tcl_DictObjPut(interp, responseDictPtr, Tcl_NewStringObj("statusCode", -1), Tcl_NewIntObj(status_code))) {
        Tcl_DecrRefCount(responseDictPtr);
        return TCL_ERROR;

    }
    if (TCL_OK != Tcl_DictObjPut(interp, responseDictPtr, Tcl_NewStringObj("body", -1), Tcl_NewStringObj(error_text, -1))) {
        Tcl_DecrRefCount(responseDictPtr);
        return TCL_ERROR;
    }

    if (TCL_OK != tws_ReturnConn(interp, conn, responseDictPtr)) {
        Tcl_DecrRefCount(responseDictPtr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(responseDictPtr);
    return TCL_OK;
}
