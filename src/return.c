/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include <unistd.h>
#include <assert.h>
#include "return.h"
#include "base64.h"
#include "conn.h"

void tws_QueueCleanupEvent();
static void tws_ShutdownConn(tws_conn_t *conn, int force);
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
    Tcl_FreeEncoding(conn->encoding);
    Tcl_Free((char *) conn);

    dataPtr->num_conns--;
}

#if TCL_MAJOR_VERSION > 8
static void tws_FreeConn(void *data) {
#else
static void tws_FreeConn(char *data) {
#endif
    tws_conn_t *conn = (tws_conn_t *) data;
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
    int count_closed = 0;

    /* The list belongs to this thread. Close through the same deferred-free
     * path as I/O callbacks, so queued or active events never see freed data. */
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(tws_GetThreadDataKey(), sizeof(tws_thread_data_t));
    tws_conn_t *curr_conn = dataPtr->firstConnPtr;
    while (curr_conn != NULL) {
        tws_conn_t *next_conn = curr_conn->nextPtr;
        if (!curr_conn->shutdown) {
            long long elapsed = milliseconds - curr_conn->latest_millis;
            if (elapsed > curr_conn->accept_ctx->server->conn_timeout_millis) {
                tws_CloseConn(curr_conn, 2);
                count_closed++;
            }
        }
        count++;

        curr_conn = next_conn;
    }

    DBG(fprintf(stderr, "reviewed count: %d closed: %d\n", count, count_closed));

    return 1;
}

static int tws_HandleCleanupEventInThread(Tcl_Event *evPtr, int flags) {
    return tws_CleanupConnections();
}

void tws_QueueCleanupEvent() {
    Tcl_ThreadId currentThreadId = Tcl_GetCurrentThread();
    DBG(fprintf(stderr, "QueueCleanupEvent: %p\n", currentThreadId));
    Tcl_Event *evPtr = (Tcl_Event *) Tcl_Alloc(sizeof(Tcl_Event));
    evPtr->proc = tws_HandleCleanupEventInThread;
    evPtr->nextPtr = NULL;
    Tcl_QueueEvent((Tcl_Event *) evPtr, TCL_QUEUE_TAIL);
}

static int tws_HandleFreeConnEventInThread(Tcl_Event *evPtr, int flags) {
    tws_event_t *connEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) connEvPtr->clientData;
    Tcl_EventuallyFree(conn, tws_FreeConn);
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
}

static void tws_ShutdownConn(tws_conn_t *conn, int force) {
    if (conn->shutdown) {
        return;
    }

    conn->shutdown = 1;
    tws_CancelConnIO(conn);
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

    DBG(fprintf(stderr, "CloseConn - client: %d force: %d keepalive: %d wait_mask: %d\n", conn->client, force,
                conn->keepalive, conn->wait_mask));

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
    conn->ready = 0;
    conn->inprogress = 0;

    if (force) {
        if (tws_UnregisterConnName(conn->handle)) {
            tws_ShutdownConn(conn, force);
            tws_QueueFreeConnEvent(conn);
        }
    } else {
        if (!conn->keepalive) {
            if (tws_UnregisterConnName(conn->handle)) {
                tws_ShutdownConn(conn, 2);
                tws_QueueFreeConnEvent(conn);
            }
        } else {
            tws_KeepaliveConn(conn);
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

    Tcl_Size reply_length = Tcl_DStringLength(&conn->inout_ds);
    const char *reply = Tcl_DStringValue(&conn->inout_ds);

    int rc = conn->accept_ctx->write_fn(conn, reply + conn->write_offset, reply_length - conn->write_offset);

    if (rc == TWS_AGAIN) {
        return 0;
    } else if (rc == TWS_ERROR) {
        conn->error = 1;
        tws_CloseConn(conn, 1);
        return 1;
    }

    // TWS_DONE
    tws_CloseConn(conn, 0);

    DBG(fprintf(stderr, "------------done\n"));
    return 1;
}

static int tws_HandleWriteEventInThread(Tcl_Event *evPtr, int flags) {
    tws_event_t *connEvPtr = (tws_event_t *) evPtr;
    tws_conn_t *conn = (tws_conn_t *) connEvPtr->clientData;

    assert(valid_conn_handle(conn));

    DBG(fprintf(stderr, "HandleWriteEventInThread: %s\n", conn->handle));

    if (conn->shutdown) {
        return 1;
    }
    if (!tws_HandleWrite(conn)) {
        if (conn->io_mask) {
            tws_WaitForConn(conn, conn->io_mask, tws_HandleWriteEventInThread);
        } else {
            tws_QueueConnEvent(conn, tws_HandleWriteEventInThread);
        }
    }
    return 1;
}

static void tws_QueueWriteEvent(tws_conn_t *conn) {
    assert(valid_conn_handle(conn));

    DBG(fprintf(stderr, "QueueWriteEvent - threadId: %p conn: %s\n", conn->threadId, conn->handle));
    conn->write_offset = 0;
    tws_StartConnTimer(conn, 0);
    tws_QueueConnEvent(conn, tws_HandleWriteEventInThread);
    DBG(fprintf(stderr, "QueueWriteEvent done - threadId: %p\n", conn->threadId));

}

int tws_ReturnConn(Tcl_Interp *interp, tws_conn_t *conn, Tcl_Obj *const responseDictPtr) {
    assert(valid_conn_handle(conn));

    if (!conn->accept_ctx || conn->shutdown) {
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
                    tws_CloseConn(conn, 1);
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
    int rc;
    if (isBase64Encoded) {

        Tcl_Size b64_body_length;
        const char *b64_body = Tcl_GetStringFromObj(bodyPtr, &b64_body_length);
        if (b64_body_length > 0) {
            body = Tcl_Alloc(3 * b64_body_length / 4 + 2);
            body_alloc = 1;
            if (base64_decode(b64_body, b64_body_length, body, &body_length)) {
//                Tcl_DStringFree(&ds);
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
//            Tcl_DStringFree(&ds);
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
//            Tcl_DStringFree(&ds);
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
    Tcl_DStringAppend(&conn->inout_ds, "\r\n", 2);
    Tcl_DStringAppend(&conn->inout_ds, "Content-Length: ", 16);
    Tcl_DStringAppend(&conn->inout_ds, content_length_str, content_length_str_len);
    Tcl_DStringAppend(&conn->inout_ds, "\r\n\r\n", 4);
    Tcl_DecrRefCount(contentLengthPtr);

    if (body_length > 0) {
        Tcl_DStringAppend(&conn->inout_ds, body, body_length);
    }

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
    if (conn->error || conn->shutdown) {
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
