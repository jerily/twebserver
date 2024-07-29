/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
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
#include "form.h"
#include "return.h"

#include <sys/socket.h> // for SOMAXCONN
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdlib.h>
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <unistd.h>
#endif

static int tws_ModuleInitialized;
static int signal_flag = 0;

static void tws_ThreadQueueTermEvent(Tcl_ThreadId threadId) {
    Tcl_Event *evPtr = (Tcl_Event *) Tcl_Alloc(sizeof(Tcl_Event));
    evPtr->proc = tws_HandleTermEventInThread;
    Tcl_ThreadQueueEvent(threadId, evPtr, TCL_QUEUE_TAIL);
    Tcl_ThreadAlert(threadId);
}

static void tws_StopServer(tws_server_t *server) {
    tws_listener_t *listener = server->first_listener_ptr;
    while(listener) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        fprintf(stderr, "closing listener->server_fd %d\n", listener->server_fd);
        Tcl_DeleteFileHandler(listener->server_fd);
        close(listener->server_fd);
#endif
        for (int i = 0; i < listener->option_num_threads; i++) {
            DBG(fprintf(stderr, "Stopping thread %p\n", listener->conn_thread_ids[i]));
            tws_ThreadQueueTermEvent(listener->conn_thread_ids[i]);
        }
        listener = listener->nextPtr;
    }

    fprintf(stderr, "Waiting for threads to exit\n");

    listener = server->first_listener_ptr;
    while(listener) {
        for (int i = 0; i < listener->option_num_threads; i++) {
            DBG(fprintf(stderr, "Waiting for thread %p\n", listener->conn_thread_ids[i]));
            if (TCL_OK != Tcl_JoinThread(listener->conn_thread_ids[i], NULL)) {
                fprintf(stderr, "Error joining thread %p\n", listener->conn_thread_ids[i]);
            }
            DBG(fprintf(stderr, "Thread %p exited\n", listener->conn_thread_ids[i]));
        }
        listener = listener->nextPtr;
    }
}

int tws_Destroy(Tcl_Interp *interp, const char *handle) {
    DBG(fprintf(stderr, "Destroy\n"));

    tws_server_t *server = tws_GetInternalFromServerName(handle);
    if (!server) {
        SetResult("server handle not found");
        return TCL_ERROR;
    }

    tws_StopServer(server);

    if (!tws_UnregisterServerName(handle)) {
        SetResult("unregister server name failed");
        return TCL_ERROR;
    }

    tws_listener_t *listener = server->first_listener_ptr;
    while(listener) {
        DBG(fprintf(stderr, "deleting listener\n"));
        Tcl_Free((char *) listener->conn_thread_ids);
        tws_listener_t *next_listener = listener->nextPtr;
        Tcl_Free((char *) listener);
        listener = next_listener;
    }

    DBG(fprintf(stderr, "listeners freed\n"));

    Tcl_DStringFree(&server->cmd_ds);
    Tcl_DStringFree(&server->script_ds);
    Tcl_DStringFree(&server->config_dict_ds);

    DBG(fprintf(stderr, "dstrings freed\n"));
    tws_FreeSslContexts();
    DBG(fprintf(stderr, "ssl contexts freed\n"));

    Tcl_DeleteCommand(interp, handle);
    Tcl_Free((char *) server);
    DBG(fprintf(stderr, "server destroyed\n"));
    return TCL_OK;
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
        if (TCL_OK != Tcl_GetSizeIntFromObj(interp, maxRequestReadBytesPtr, &server_ctx->max_request_read_bytes)) {
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
        if (TCL_OK != Tcl_GetSizeIntFromObj(interp, maxReadBufferSizePtr, &server_ctx->max_read_buffer_size)) {
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
        if (TCL_OK != Tcl_GetSizeIntFromObj(interp, backlogPtr, &server_ctx->backlog)) {
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
            SetResult("conn_timeout_millis must be an integer");
            return TCL_ERROR;
        }
    }


    Tcl_Obj *readTimeoutMillisPtr;
    Tcl_Obj *readTimeoutMillisKeyPtr = Tcl_NewStringObj("read_timeout_millis", -1);
    Tcl_IncrRefCount(readTimeoutMillisKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, readTimeoutMillisKeyPtr, &readTimeoutMillisPtr)) {
        Tcl_DecrRefCount(readTimeoutMillisKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(readTimeoutMillisKeyPtr);
    if (readTimeoutMillisPtr) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, readTimeoutMillisPtr, &server_ctx->read_timeout_millis)) {
            SetResult("read_timeout_millis must be an integer");
            return TCL_ERROR;
        }
    }

    // check that conn_timeout_millis is between 1 and 1 hour
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

    Tcl_Obj *garbageCollectionCleanupThresholdPtr;
    Tcl_Obj *garbageCollectionCleanupThresholdKeyPtr = Tcl_NewStringObj("garbage_collection_cleanup_threshold", -1);
    Tcl_IncrRefCount(garbageCollectionCleanupThresholdKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, configDictPtr, garbageCollectionCleanupThresholdKeyPtr,
                                 &garbageCollectionCleanupThresholdPtr)) {
        Tcl_DecrRefCount(garbageCollectionCleanupThresholdKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(garbageCollectionCleanupThresholdKeyPtr);
    if (garbageCollectionCleanupThresholdPtr) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, garbageCollectionCleanupThresholdPtr,
                                        &server_ctx->garbage_collection_cleanup_threshold)) {
            SetResult("garbage_collection_interval_millis must be an integer");
            return TCL_ERROR;
        }
    }

    // check that garbage_collection_interval_millis is between 1 and 1 hour
    if (server_ctx->garbage_collection_cleanup_threshold < 1) {
        SetResult("garbage_collection_cleanup_threshold must be greater than zero");
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
        if (TCL_OK != Tcl_GetSizeIntFromObj(interp, gzipMinLengthPtr, &server_ctx->gzip_min_length)) {
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
        Tcl_Size gzip_types_count;
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
    if (server_ctx->num_threads <= 0) {
        SetResult("num_threads must be > 0");
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
        if (TCL_OK != Tcl_GetSizeIntFromObj(interp, threadStacksizePtr, &server_ctx->thread_stacksize)) {
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

static int tws_CreateServerCmd(ClientData clientData, Tcl_Interp *interp, int incoming_objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "CreateCmd\n"));

    int option_router = 0;
    Tcl_ArgvInfo ArgTable[] = {
            {TCL_ARGV_CONSTANT, "-with_router", INT2PTR(1), &option_router, "whether cmd_name is a router"},
            {TCL_ARGV_END, NULL,         NULL, NULL, NULL}
    };

    Tcl_Obj **remObjv;
    Tcl_Size objc = incoming_objc;
    Tcl_ParseArgsObjv(interp, ArgTable, &objc, objv, &remObjv);

    if ((objc < 4) || (objc > 4)) {
        ckfree(remObjv);
        Tcl_WrongNumArgs(interp, 1, remObjv, "config_dict cmd_name init_script");
        return TCL_ERROR;
    }

    tws_server_t *server_ptr = (tws_server_t *) Tcl_Alloc(sizeof(tws_server_t));
    if (!server_ptr) {
        ckfree(remObjv);
        SetResult("Unable to allocate memory");
        return TCL_ERROR;
    }

    DBG(fprintf(stderr, "option_router=%d\n", option_router));

    server_ptr->option_router = option_router;
    Tcl_DStringInit(&server_ptr->config_dict_ds);
    Tcl_DStringAppend(&server_ptr->config_dict_ds, Tcl_GetString(remObjv[1]), -1);
    Tcl_DStringInit(&server_ptr->cmd_ds);
    Tcl_DStringAppend(&server_ptr->cmd_ds, Tcl_GetString(remObjv[2]), -1);
    Tcl_DStringInit(&server_ptr->script_ds);
    Tcl_DStringAppend(&server_ptr->script_ds, Tcl_GetString(remObjv[3]), -1);

    server_ptr->thread_id = Tcl_GetCurrentThread();
    server_ptr->first_listener_ptr = NULL;

    // configuration
    server_ptr->max_request_read_bytes = 10 * 1024 * 1024;
    server_ptr->max_read_buffer_size = 32 * 1024;
    server_ptr->backlog = SOMAXCONN;
    server_ptr->conn_timeout_millis = 2 * 60 * 1000;  // 2 minutes
    server_ptr->read_timeout_millis = 30 * 1000;  // 30 seconds
    server_ptr->garbage_collection_cleanup_threshold = 10 * 1000;  // attempt cleanup every 10000 requests
    server_ptr->garbage_collection_interval_millis = 10 * 1000;  // 10 seconds
    server_ptr->keepalive = 1;
    server_ptr->keepidle = 10;
    server_ptr->keepintvl = 5;
    server_ptr->keepcnt = 3;
    server_ptr->gzip = 1;
    server_ptr->gzip_min_length = 8192;
    Tcl_InitHashTable(&server_ptr->gzip_types_HT, TCL_STRING_KEYS);

    Tcl_HashEntry *entryPtr;
    int newEntry;
    entryPtr = Tcl_CreateHashEntry(&server_ptr->gzip_types_HT, "text/html", &newEntry);
    if (newEntry) {
        Tcl_SetHashValue(entryPtr, (ClientData) NULL);
    }

    server_ptr->num_threads = 10;
    server_ptr->thread_stacksize = TCL_THREAD_STACK_DEFAULT;
    server_ptr->thread_max_concurrent_conns = 0;

    if (TCL_OK != tws_InitServerFromConfigDict(interp, server_ptr, remObjv[1])) {
        Tcl_Free((char *) server_ptr);
        return TCL_ERROR;
    }

    CMD_SERVER_NAME(server_ptr->handle, server_ptr);
    tws_RegisterServerName(server_ptr->handle, server_ptr);

    SetResult(server_ptr->handle);
    return TCL_OK;

}

static int tws_DestroyServerCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "DestroyCmd\n"));
    CheckArgs(2, 2, 1, "handle");

    return tws_Destroy(interp, Tcl_GetString(objv[1]));

}

static int tws_ListenCmd(ClientData clientData, Tcl_Interp *interp, int incoming_objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "ListenCmd\n"));

    int option_http = 0;
    int option_num_threads = 0;
    const char *host = NULL;
    Tcl_ArgvInfo ArgTable[] = {
            {TCL_ARGV_CONSTANT, "-http", INT2PTR(1), &option_http, "http (not https) listener"},
            {TCL_ARGV_INT, "-num_threads", NULL, &option_num_threads, "num threads for listener"},
            {TCL_ARGV_STRING, "-host", NULL, &host, "host for listener"},
            {TCL_ARGV_END, NULL,         NULL, NULL, NULL}
    };
    Tcl_Obj **remObjv;
    Tcl_Size objc = incoming_objc;
    Tcl_ParseArgsObjv(interp, ArgTable, &objc, objv, &remObjv);

    if ((objc < 3) || (objc > 3)) {
        ckfree(remObjv);
        Tcl_WrongNumArgs(interp, 1, remObjv, "server_handle port");
        return TCL_ERROR;
    }

    const char *handle = Tcl_GetString(remObjv[1]);
    tws_server_t *server = tws_GetInternalFromServerName(handle);
    if (!server) {
        ckfree(remObjv);
        SetResult("server handle not found");
        return TCL_ERROR;
    }

    if (option_num_threads == 0) {
        option_num_threads = server->num_threads;
    }

    int port_num;
    if (Tcl_GetIntFromObj(interp, remObjv[2], &port_num) != TCL_OK) {
        SetResult("port must be an integer");
        return TCL_ERROR;
    }

    if (port_num < 0 || port_num > 65535) {
        SetResult("port must be between 0 and 65535");
        return TCL_ERROR;
    }

    const char *port = Tcl_GetString(remObjv[2]);

    int result = tws_Listen(interp, server, option_http, option_num_threads, host, port);
    ckfree(remObjv);
    return result;

}

static int tws_AddContextCmd(ClientData clientData, Tcl_Interp *interp, int incoming_objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AddContextCmd\n"));

    int option_verify_client = 0;
    char *cafile = NULL;
    char *cadir = NULL;
    Tcl_ArgvInfo ArgTable[] = {
            {TCL_ARGV_CONSTANT, "-verify_client", INT2PTR(1), &option_verify_client, "enables client verification"},
            {TCL_ARGV_STRING, "-cafile", NULL, &cafile, "CA file for client verification"},
            {TCL_ARGV_STRING, "-cadir", NULL, &cadir, "CA directory for client verification"},
            {TCL_ARGV_END, NULL,         NULL, NULL, NULL}
    };

    Tcl_Obj **remObjv;
    Tcl_Size objc = incoming_objc;
    Tcl_ParseArgsObjv(interp, ArgTable, &objc, objv, &remObjv);

    if ((objc < 5) || (objc > 5)) {
        ckfree(remObjv);
        Tcl_WrongNumArgs(interp, 1, remObjv, "server_handle hostname key cert");
        return TCL_ERROR;
    }

    Tcl_Size handle_len;
    const char *handle = Tcl_GetStringFromObj(remObjv[1], &handle_len);

    tws_server_t *server = tws_GetInternalFromServerName(handle);
    if (!server) {
        ckfree(remObjv);
        SetResult("server handle not found");
        return TCL_ERROR;
    }

    Tcl_Size hostname_len;
    const char *hostname = Tcl_GetStringFromObj(remObjv[2], &hostname_len);
    if (hostname_len == 0) {
        ckfree(remObjv);
        SetResult("hostname must not be empty");
        return TCL_ERROR;
    }

    Tcl_Size keyfile_len;
    const char *keyfile = Tcl_GetStringFromObj(remObjv[3], &keyfile_len);
    if (keyfile_len == 0) {
        ckfree(remObjv);
        SetResult("keyfile must not be empty");
        return TCL_ERROR;
    }

    Tcl_Size certfile_len;
    const char *certfile = Tcl_GetStringFromObj(remObjv[4], &certfile_len);
    if (certfile_len == 0) {
        ckfree(remObjv);
        SetResult("certfile must not be empty");
        return TCL_ERROR;
    }

    if (option_verify_client) {
        if (cafile == NULL || cadir == NULL) {
            ckfree(remObjv);
            SetResult("CA file or CA directory not set - required when verify_client is set");
            return TCL_ERROR;
        }
    }

    SSL_CTX *ctx;
    if (TCL_OK != tws_CreateSslContext(interp, &ctx)) {
        ckfree(remObjv);
        return TCL_ERROR;
    }
    if (TCL_OK != tws_ConfigureSslContext(interp, ctx, keyfile, certfile)) {
        SSL_CTX_free(ctx);
        ckfree(remObjv);
        return TCL_ERROR;
    }

    if (option_verify_client) {

        // Require client certificate verification
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        SSL_CTX_set_verify_depth(ctx, 1);

        // Load CA certificate to verify client
        if (!SSL_CTX_load_verify_locations(ctx, cafile, cadir)) {
            SSL_CTX_free(ctx);
            ERR_print_errors_fp(stderr);
            ckfree(remObjv);
            SetResult("Unable to load CA certificate");
            return TCL_ERROR;
        }

    }

    tws_RegisterHostName(hostname, ctx);

    ckfree(remObjv);
    return TCL_OK;
}

static int tws_EncodeURIComponentCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "EncodeURIComponentCmd\n"));
    CheckArgs(2, 2, 1, "text");

    int enc_flags = CHAR_COMPONENT;

    Tcl_Size length;
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

    Tcl_Size length;
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

    Tcl_Size length;
    const char *encoded_text = Tcl_GetStringFromObj(objv[1], &length);

    Tcl_Encoding encoding;
    if (objc == 3) {
        encoding = Tcl_GetEncoding(interp, Tcl_GetString(objv[2]));
    } else {
        encoding = Tcl_GetEncoding(interp, "utf-8");
    }

    Tcl_DString value_ds;
    Tcl_DStringInit(&value_ds);

    int error_num = 0;
    if (TCL_OK != tws_UrlDecode(encoding, encoded_text, length, &value_ds, &error_num)) {
        Tcl_DStringFree(&value_ds);
        SetResult(tws_parse_error_messages[error_num]);
        return TCL_ERROR;
    }
    Tcl_DStringResult(interp, &value_ds);
    Tcl_DStringFree(&value_ds);
    return TCL_OK;
}

static int tws_Base64EncodeCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "Base64EncodeCmd\n"));
    CheckArgs(2, 2, 1, "bytes");

    Tcl_Size input_length;
    const unsigned char *input = Tcl_GetByteArrayFromObj(objv[1], &input_length);

    if (input_length == 0) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("", 0));
        return TCL_OK;
    }

    char *output = Tcl_Alloc(input_length * 2);
    Tcl_Size output_length;
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

    Tcl_Size input_length;
    const char *input = Tcl_GetStringFromObj(objv[1], &input_length);

    char *output = Tcl_Alloc(3 * input_length / 4 + 2);
    Tcl_Size output_length;
    if (base64_decode(input, input_length, output, &output_length)) {
        Tcl_Free(output);
        SetResult("base64_decode failed");
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(output, output_length));
    Tcl_Free(output);
    return TCL_OK;
}

static int tws_AddHeader(Tcl_Interp *interp, Tcl_Obj *const responseDictPtr, Tcl_Obj *headerNamePtr, Tcl_Obj *headerValuePtr,
                         Tcl_Obj **resultPtr) {
    Tcl_Obj *dupResponseDictPtr = Tcl_DuplicateObj(responseDictPtr);
    Tcl_IncrRefCount(dupResponseDictPtr);

    // check if the header exists in "multiValueHeaders" first
    Tcl_Obj *multiValueHeadersPtr;
    Tcl_Obj *multiValueHeadersKeyPtr = Tcl_NewStringObj("multiValueHeaders", -1);
    Tcl_IncrRefCount(multiValueHeadersKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, dupResponseDictPtr, multiValueHeadersKeyPtr, &multiValueHeadersPtr)) {
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

        if (TCL_OK != Tcl_DictObjPut(interp, dupResponseDictPtr, multiValueHeadersKeyPtr, multiValueHeadersPtr)) {
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
    if (TCL_OK != Tcl_DictObjGet(interp, dupResponseDictPtr, headersKeyPtr, &headersPtr)) {
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
            Tcl_IncrRefCount(listValuePtr);
            if (TCL_OK != Tcl_ListObjAppendElement(interp, listValuePtr, valuePtr)
                || TCL_OK != Tcl_ListObjAppendElement(interp, listValuePtr, headerValuePtr)) {
                Tcl_DecrRefCount(headersKeyPtr);
                Tcl_DecrRefCount(multiValueHeadersKeyPtr);
                Tcl_DecrRefCount(dupResponseDictPtr);
                Tcl_DecrRefCount(listValuePtr);
                SetResult("add_header: error appending to list while creating multiValueHeaders");
                return TCL_ERROR;
            }

            // create "multiValueHeaders" dict
            Tcl_Obj *newMultiValueHeadersPtr = Tcl_NewDictObj();
            Tcl_IncrRefCount(newMultiValueHeadersPtr);
            if (TCL_OK != Tcl_DictObjPut(interp, newMultiValueHeadersPtr, headerNamePtr, listValuePtr)) {
                Tcl_DecrRefCount(headersKeyPtr);
                Tcl_DecrRefCount(multiValueHeadersKeyPtr);
                Tcl_DecrRefCount(dupResponseDictPtr);
                Tcl_DecrRefCount(listValuePtr);
                Tcl_DecrRefCount(newMultiValueHeadersPtr);
                SetResult("add_header: error writing new list value to multiValueHeaders");
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(listValuePtr);

            // write "multiValueHeaders" dict to response dict
            if (TCL_OK != Tcl_DictObjPut(interp, dupResponseDictPtr, multiValueHeadersKeyPtr, newMultiValueHeadersPtr)) {
                Tcl_DecrRefCount(headersKeyPtr);
                Tcl_DecrRefCount(multiValueHeadersKeyPtr);
                Tcl_DecrRefCount(dupResponseDictPtr);
                Tcl_DecrRefCount(newMultiValueHeadersPtr);
                SetResult("add_header: error writing multiValueHeaders back to response dict");
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(newMultiValueHeadersPtr);

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
            Tcl_DecrRefCount(dupHeadersPtr);

            // we are done
        }
    } else {
        // create "headersPtr" dict
        headersPtr = Tcl_NewDictObj();
        Tcl_IncrRefCount(headersPtr);
        if (TCL_OK != Tcl_DictObjPut(interp, headersPtr, headerNamePtr, headerValuePtr)) {
            Tcl_DecrRefCount(headersKeyPtr);
            Tcl_DecrRefCount(multiValueHeadersKeyPtr);
            Tcl_DecrRefCount(dupResponseDictPtr);
            Tcl_DecrRefCount(headersPtr);
            SetResult("add_header: error writing value to headers");
            return TCL_ERROR;
        }

        // write "headersPtr" to response dict
        if (TCL_OK != Tcl_DictObjPut(interp, dupResponseDictPtr, headersKeyPtr, headersPtr)) {
            Tcl_DecrRefCount(headersKeyPtr);
            Tcl_DecrRefCount(multiValueHeadersKeyPtr);
            Tcl_DecrRefCount(dupResponseDictPtr);
            Tcl_DecrRefCount(headersPtr);
            SetResult("add_header: error writing headers back to response dict");
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(headersPtr);

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

    Tcl_Size cookie_header_len;
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

        Tcl_DString value_ds;
        Tcl_DStringInit(&value_ds);
        if (s != t) {

            int error_num = 0;
            if (TCL_OK != tws_UrlDecode(encoding, s + 1, t - s - 1, &value_ds, &error_num)) {
                Tcl_DecrRefCount(keyPtr);
                Tcl_DecrRefCount(cookie_dict);
                Tcl_DStringFree(&value_ds);
                SetResult(tws_parse_error_messages[error_num]);
                return TCL_ERROR;
            }
        }

        if (TCL_OK != Tcl_DictObjPut(interp, cookie_dict, keyPtr, Tcl_NewStringObj(Tcl_DStringValue(&value_ds), Tcl_DStringLength(&value_ds)))) {
            Tcl_DecrRefCount(keyPtr);
            Tcl_DecrRefCount(cookie_dict);
            Tcl_DStringFree(&value_ds);
            SetResult("error adding key-value pair to cookie_dict");
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(keyPtr);
        Tcl_DStringFree(&value_ds);

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


static int tws_ParseQueryCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "ParseCookieCmd\n"));
    CheckArgs(2, 3, 1, "query_string ?encoding?");

    Tcl_Size query_string_len;
    const char *query_string = Tcl_GetStringFromObj(objv[1], &query_string_len);

    const char *encoding_name = "utf-8";
    if (objc == 3) {
        encoding_name = Tcl_GetString(objv[2]);
    }

    Tcl_DString parse_ds;
    Tcl_DStringInit(&parse_ds);

    int error_num = 0;
    if (TCL_OK != tws_ParseQueryStringParameters(Tcl_GetEncoding(interp, encoding_name), query_string, query_string_len, &parse_ds, &error_num)) {
        Tcl_DStringFree(&parse_ds);
        SetResult(tws_parse_error_messages[error_num]);
        return TCL_ERROR;
    }

    Tcl_DStringResult(interp, &parse_ds);
    Tcl_DStringFree(&parse_ds);
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

static int tws_AddCookieCmd(ClientData clientData, Tcl_Interp *interp, int incoming_objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AddCookieCmd\n"));

    const char *option_path = NULL;
    const char *option_domain = NULL;
    const char *option_samesite = NULL;
    const char *option_expires = NULL;
    int option_maxage = -1;
    int option_httponly = 0;
    int option_partitioned = 0;
    int option_insecure = 0;
    Tcl_ArgvInfo ArgTable[] = {
            {TCL_ARGV_STRING,   "-path",        NULL,       &option_path,        "value for the Path attribute"},
            {TCL_ARGV_STRING,   "-domain",      NULL,       &option_domain,      "value for the Domain attribute"},
            {TCL_ARGV_STRING,   "-samesite",    NULL,       &option_samesite,    "value for the SameSite attribute"},
            {TCL_ARGV_STRING,   "-expires",    NULL,       &option_expires,    "value for the Expires attribute"},
            {TCL_ARGV_INT,      "-maxage",      NULL,       &option_maxage,      "number of seconds until the cookie expires"},
            {TCL_ARGV_CONSTANT, "-httponly",    INT2PTR(1), &option_httponly,    "HttpOnly attribute is set"},
            {TCL_ARGV_CONSTANT, "-partitioned", INT2PTR(1), &option_partitioned, "indicates that the cookie should be stored using partitioned storage"},
            {TCL_ARGV_CONSTANT, "-insecure",    INT2PTR(1), &option_insecure,    "indicates whether to not set the Secure attribute"},
            {TCL_ARGV_END, NULL,                NULL, NULL, NULL}
    };

    Tcl_Obj **remObjv;
    Tcl_Size objc = incoming_objc;
    Tcl_ParseArgsObjv(interp, ArgTable, &objc, objv, &remObjv);

    if ((objc < 4) || (objc > 4)) {
        ckfree(remObjv);
        Tcl_WrongNumArgs(interp, 1, remObjv, "response_dict cookie_name cookie_value");
        return TCL_ERROR;
    }

    Tcl_DString header_value_ds;
    Tcl_DStringInit(&header_value_ds);

    // append cookie name and value to headerValuePtr
    Tcl_Size cookie_name_length;
    const char *cookie_name = Tcl_GetStringFromObj(remObjv[2], &cookie_name_length);
    Tcl_DStringAppend(&header_value_ds, cookie_name, cookie_name_length);
    Tcl_DStringAppend(&header_value_ds, "=", 1);

    // encode the cookie value
    int enc_flags = CHAR_COMPONENT;
    Tcl_Obj *cookieValuePtr;
    Tcl_Size cookie_value_length;
    const char *cookie_value = Tcl_GetStringFromObj(remObjv[3], &cookie_value_length);
    if (TCL_OK != tws_UrlEncode(interp, enc_flags, cookie_value, cookie_value_length, &cookieValuePtr)) {
        ckfree(remObjv);
        Tcl_DStringFree(&header_value_ds);
        return TCL_ERROR;
    }
    Tcl_Size ue_cookie_value_length;
    const char *ue_cookie_value = Tcl_GetStringFromObj(cookieValuePtr, &ue_cookie_value_length);
    Tcl_DStringAppend(&header_value_ds, ue_cookie_value, ue_cookie_value_length);
    Tcl_DecrRefCount(cookieValuePtr);
    // append Domain
    if (option_domain) {
        Tcl_DStringAppend(&header_value_ds, "; Domain=", 9);
        Tcl_DStringAppend(&header_value_ds, option_domain, -1);
    }

    // append Path
    if (option_path) {
        Tcl_DStringAppend(&header_value_ds, "; Path=", 7);
        Tcl_DStringAppend(&header_value_ds, option_path, -1);
    } else {
        Tcl_DStringAppend(&header_value_ds, "; Path=/", 8);
    }

    // append SameSite
    if (option_samesite) {
        Tcl_DStringAppend(&header_value_ds, "; SameSite=", 11);
        Tcl_DStringAppend(&header_value_ds, option_samesite, -1);
    }

    // append Expires
    if (option_expires) {
        Tcl_DStringAppend(&header_value_ds, "; Expires=", 10);
        Tcl_DStringAppend(&header_value_ds, option_expires, -1);
    }

    // append Secure
    if (!option_insecure) {
        Tcl_DStringAppend(&header_value_ds, "; Secure", 8);
    }

    // append HttpOnly
    if (option_httponly) {
        Tcl_DStringAppend(&header_value_ds, "; HttpOnly", 10);
    }

    // append Partitioned
    if (option_partitioned) {
        Tcl_DStringAppend(&header_value_ds, "; Partitioned", 12);
    }

    // append Max-Age
    if (option_maxage >= 0) {
        Tcl_DStringAppend(&header_value_ds, "; Max-Age=", 10);
        Tcl_Obj *option_maxage_ptr = Tcl_NewIntObj(option_maxage);
        Tcl_IncrRefCount(option_maxage_ptr);
        Tcl_DStringAppend(&header_value_ds, Tcl_GetString(option_maxage_ptr), -1);
        Tcl_DecrRefCount(option_maxage_ptr);
    }

    Tcl_Obj *header_value_ptr = Tcl_NewStringObj(Tcl_DStringValue(&header_value_ds), Tcl_DStringLength(&header_value_ds));
    Tcl_IncrRefCount(header_value_ptr);
    Tcl_DStringFree(&header_value_ds);

    Tcl_Obj *header_name_ptr = Tcl_NewStringObj("Set-Cookie", 10);
    Tcl_IncrRefCount(header_name_ptr);

    Tcl_Obj *response_dict_ptr;
    if (TCL_OK != tws_AddHeader(interp, remObjv[1], header_name_ptr, header_value_ptr, &response_dict_ptr)) {
        ckfree(remObjv);
        Tcl_DecrRefCount(header_value_ptr);
        Tcl_DecrRefCount(header_name_ptr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(header_value_ptr);
    Tcl_DecrRefCount(header_name_ptr);
    ckfree(remObjv);

    Tcl_SetObjResult(interp, response_dict_ptr);
    Tcl_DecrRefCount(response_dict_ptr);
    return TCL_OK;
}

static int tws_BuildResponseCmd(ClientData clientData, Tcl_Interp *interp, int incoming_objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "BuildResponseCmd\n"));

    int option_file = 0;
    Tcl_ArgvInfo ArgTable[] = {
            {TCL_ARGV_CONSTANT, "-return_file",    INT2PTR(1), &option_file,    "indicates whether the last parameter is a file path"},
            {TCL_ARGV_END, NULL,                NULL, NULL, NULL}
    };

    Tcl_Obj **remObjv;
    Tcl_Size objc = incoming_objc;
    Tcl_ParseArgsObjv(interp, ArgTable, &objc, objv, &remObjv);

    if ((objc < 4) || (objc > 4)) {
        ckfree(remObjv);
        Tcl_WrongNumArgs(interp, 1, remObjv, "status_code mimetype body");
        return TCL_ERROR;
    }

    Tcl_Obj *response_dict_ptr = Tcl_NewDictObj();
    Tcl_IncrRefCount(response_dict_ptr);

    Tcl_Obj *status_code_key_ptr = Tcl_NewStringObj("statusCode", -1);
    Tcl_IncrRefCount(status_code_key_ptr);
    if (TCL_OK != Tcl_DictObjPut(interp, response_dict_ptr, status_code_key_ptr, remObjv[1])) {
        Tcl_DecrRefCount(status_code_key_ptr);
        Tcl_DecrRefCount(response_dict_ptr);
        ckfree(remObjv);
        SetResult("build_response: error writing status_code to response_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(status_code_key_ptr);

    Tcl_Obj *headers_key_ptr = Tcl_NewStringObj("headers", -1);
    Tcl_IncrRefCount(headers_key_ptr);
    Tcl_Obj *headers_dict_ptr = Tcl_NewDictObj();
    Tcl_IncrRefCount(headers_dict_ptr);

    Tcl_Obj *content_type_key_ptr = Tcl_NewStringObj("Content-Type", -1);
    Tcl_IncrRefCount(content_type_key_ptr);
    if (TCL_OK != Tcl_DictObjPut(interp, headers_dict_ptr, content_type_key_ptr, remObjv[2])) {
        Tcl_DecrRefCount(content_type_key_ptr);
        Tcl_DecrRefCount(headers_dict_ptr);
        Tcl_DecrRefCount(headers_key_ptr);
        Tcl_DecrRefCount(response_dict_ptr);
        ckfree(remObjv);
        SetResult("build_response: error writing Content-Type to headers_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(content_type_key_ptr);

    if (TCL_OK != Tcl_DictObjPut(interp, response_dict_ptr, headers_key_ptr, headers_dict_ptr)) {
        Tcl_DecrRefCount(headers_key_ptr);
        Tcl_DecrRefCount(headers_dict_ptr);
        Tcl_DecrRefCount(response_dict_ptr);
        ckfree(remObjv);
        SetResult("build_response: error writing headers to response_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(headers_key_ptr);
    Tcl_DecrRefCount(headers_dict_ptr);

    Tcl_Size mimetype_length;
    const char *mimetype = Tcl_GetStringFromObj(remObjv[2], &mimetype_length);
    int is_binary_type = tws_IsBinaryType(mimetype, mimetype_length);

    Tcl_Obj *input_ptr;
    if (option_file) {
        // read the file denoted by the last parameter

        Tcl_Size filename_length;
        const char *filename = Tcl_GetStringFromObj(remObjv[3], &filename_length);
        const char *mode_string = is_binary_type ? "rb" : "r";

        struct stat statbuf;
        if (Tcl_Stat(filename, &statbuf) != 0) {
            Tcl_DecrRefCount(response_dict_ptr);
            ckfree(remObjv);
            SetResult("build_response: error stating file");
            return TCL_ERROR;
        }

        Tcl_Size file_data_length = statbuf.st_size;

        Tcl_Channel channel = Tcl_OpenFileChannel(interp, filename, mode_string, 0);
        if (channel == NULL) {
            Tcl_DecrRefCount(response_dict_ptr);
            ckfree(remObjv);
            SetResult("build_response: error opening file");
            return TCL_ERROR;
        }

        char *file_data = Tcl_Alloc(file_data_length);
        Tcl_Size bytes_read = Tcl_ReadRaw(channel, file_data, file_data_length);
        if (bytes_read < 0) {
            Tcl_Free(file_data);
            Tcl_DecrRefCount(response_dict_ptr);
            ckfree(remObjv);
            SetResult("build_response: error reading file");
            return TCL_ERROR;
        }

        // close channel
        Tcl_Close(interp, channel);

        input_ptr = is_binary_type ?
                Tcl_NewByteArrayObj(file_data, file_data_length)
                : Tcl_NewStringObj(file_data, file_data_length);

        Tcl_IncrRefCount(input_ptr);
        Tcl_Free(file_data);
    } else {
        input_ptr = remObjv[3];
    }

    if (is_binary_type) {

        // set the "isBase64Encoded" key to 1
        Tcl_Obj *is_base64_encoded_key_ptr = Tcl_NewStringObj("isBase64Encoded", -1);
        Tcl_IncrRefCount(is_base64_encoded_key_ptr);
        if (TCL_OK != Tcl_DictObjPut(interp, response_dict_ptr, is_base64_encoded_key_ptr, Tcl_NewBooleanObj(1))) {
            if (option_file) {
                Tcl_DecrRefCount(input_ptr);
            }
            Tcl_DecrRefCount(is_base64_encoded_key_ptr);
            Tcl_DecrRefCount(response_dict_ptr);
            ckfree(remObjv);
            SetResult("build_response: error writing isBase64Encoded to response_dict");
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(is_base64_encoded_key_ptr);

        // base64 encode the body
        Tcl_Size input_length;
        const char *input = Tcl_GetByteArrayFromObj(input_ptr, &input_length);
        char *output = Tcl_Alloc(input_length * 2);
        size_t output_length;
        if (TCL_OK != base64_encode(input, input_length, output, &output_length)) {
            if (option_file) {
                Tcl_DecrRefCount(input_ptr);
            }
            Tcl_Free(output);
            Tcl_DecrRefCount(response_dict_ptr);
            ckfree(remObjv);
            SetResult("build_response: error base64 encoding body");
            return TCL_ERROR;
        }

        Tcl_Obj *value_ptr = Tcl_NewStringObj(output, output_length);
        Tcl_IncrRefCount(value_ptr);
        Tcl_Obj *body_key_ptr = Tcl_NewStringObj("body", -1);
        Tcl_IncrRefCount(body_key_ptr);
        if (TCL_OK != Tcl_DictObjPut(interp, response_dict_ptr, body_key_ptr, value_ptr)) {
            if (option_file) {
                Tcl_DecrRefCount(input_ptr);
            }
            Tcl_DecrRefCount(body_key_ptr);
            Tcl_DecrRefCount(value_ptr);
            Tcl_DecrRefCount(response_dict_ptr);
            Tcl_Free(output);
            ckfree(remObjv);
            SetResult("build_response: error writing body to response_dict");
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(body_key_ptr);
        Tcl_DecrRefCount(value_ptr);
        Tcl_Free(output);

    } else {
        Tcl_Obj *body_key_ptr = Tcl_NewStringObj("body", -1);
        Tcl_IncrRefCount(body_key_ptr);
        if (TCL_OK != Tcl_DictObjPut(interp, response_dict_ptr, body_key_ptr, input_ptr)) {
            if (option_file) {
                Tcl_DecrRefCount(input_ptr);
            }
            Tcl_DecrRefCount(body_key_ptr);
            Tcl_DecrRefCount(response_dict_ptr);
            ckfree(remObjv);
            SetResult("build_response: error writing body to response_dict");
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(body_key_ptr);
    }

    Tcl_SetObjResult(interp, response_dict_ptr);
    if (option_file) {
        Tcl_DecrRefCount(input_ptr);
    }
    Tcl_DecrRefCount(response_dict_ptr);
    ckfree(remObjv);
    return TCL_OK;
}

static int tws_BuildRedirectCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "BuildRedirectCmd\n"));
    CheckArgs(3, 3, 1, "status_code location");

    // check status_code is 301 or 302
    int status_code;
    if (TCL_OK != Tcl_GetIntFromObj(interp, objv[1], &status_code)) {
        return TCL_ERROR;
    }

    if (status_code != 301 && status_code != 302) {
        SetResult("build_redirect: status_code must be 301 or 302");
        return TCL_ERROR;
    }

    Tcl_Obj *response_dict_ptr = Tcl_NewDictObj();
    Tcl_IncrRefCount(response_dict_ptr);

    Tcl_Obj *status_code_key_ptr = Tcl_NewStringObj("statusCode", -1);
    Tcl_IncrRefCount(status_code_key_ptr);
    if (TCL_OK != Tcl_DictObjPut(interp, response_dict_ptr, status_code_key_ptr, objv[1])) {
        Tcl_DecrRefCount(status_code_key_ptr);
        Tcl_DecrRefCount(response_dict_ptr);
        SetResult("build_redirect: error writing status_code to response_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(status_code_key_ptr);

    Tcl_Obj *headers_key_ptr = Tcl_NewStringObj("headers", -1);
    Tcl_IncrRefCount(headers_key_ptr);
    Tcl_Obj *headers_dict_ptr = Tcl_NewDictObj();
    Tcl_IncrRefCount(headers_dict_ptr);

    Tcl_Obj *location_key_ptr = Tcl_NewStringObj("Location", -1);
    Tcl_IncrRefCount(location_key_ptr);
    if (TCL_OK != Tcl_DictObjPut(interp, headers_dict_ptr, location_key_ptr, objv[2])) {
        Tcl_DecrRefCount(location_key_ptr);
        Tcl_DecrRefCount(headers_dict_ptr);
        Tcl_DecrRefCount(headers_key_ptr);
        Tcl_DecrRefCount(response_dict_ptr);
        SetResult("build_redirect: error writing Location to headers_dict");
        return TCL_ERROR;
    }

    if (TCL_OK != Tcl_DictObjPut(interp, response_dict_ptr, headers_key_ptr, headers_dict_ptr)) {
        Tcl_DecrRefCount(headers_key_ptr);
        Tcl_DecrRefCount(headers_dict_ptr);
        Tcl_DecrRefCount(response_dict_ptr);
        SetResult("build_redirect: error writing headers to response_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(headers_key_ptr);
    Tcl_DecrRefCount(headers_dict_ptr);

    Tcl_Obj *body_key_ptr = Tcl_NewStringObj("body", -1);
    Tcl_IncrRefCount(body_key_ptr);
    if (TCL_OK != Tcl_DictObjPut(interp, response_dict_ptr, body_key_ptr, Tcl_NewStringObj("", -1))) {
        Tcl_DecrRefCount(body_key_ptr);
        Tcl_DecrRefCount(response_dict_ptr);
        SetResult("build_response: error writing body to response_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(body_key_ptr);

    Tcl_SetObjResult(interp, response_dict_ptr);
    Tcl_DecrRefCount(response_dict_ptr);
    return TCL_OK;
}

static int tws_GetQueryParam(Tcl_Interp *interp, Tcl_Obj *req_dict_ptr, Tcl_Obj *param_name_ptr, int option_multi, Tcl_Obj **result_ptr) {
    // Check request_dict for the following keys:
    //    multiValueQueryStringParameters
    //    queryStringParameters

    // If "multiValueQueryStringParameters" exists, check if "param_name" is part of it and return it

    Tcl_Obj *multi_value_query_string_parameters_key_ptr = Tcl_NewStringObj("multiValueQueryStringParameters", -1);
    Tcl_IncrRefCount(multi_value_query_string_parameters_key_ptr);
    Tcl_Obj *multi_value_query_string_parameters_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, req_dict_ptr, multi_value_query_string_parameters_key_ptr,
                                 &multi_value_query_string_parameters_ptr)) {
        Tcl_DecrRefCount(multi_value_query_string_parameters_key_ptr);
        SetResult("get_query_param: error reading multiValueQueryStringParameters from request_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(multi_value_query_string_parameters_key_ptr);

    if (multi_value_query_string_parameters_ptr) {
        // check if "param_name" is part of it and return it
        Tcl_Obj *listValuePtr;
        if (TCL_OK != Tcl_DictObjGet(interp, multi_value_query_string_parameters_ptr, param_name_ptr, &listValuePtr)) {
            SetResult("get_query_param: error reading param_name from multiValueQueryStringParameters");
            return TCL_ERROR;
        }
        if (listValuePtr) {
            Tcl_IncrRefCount(listValuePtr);
            *result_ptr = listValuePtr;
            return TCL_OK;
        }
    }

    // If queryStringParameters exists, check if "param_name" is part of it and return it

    Tcl_Obj *query_string_parameters_key_ptr = Tcl_NewStringObj("queryStringParameters", -1);
    Tcl_IncrRefCount(query_string_parameters_key_ptr);
    Tcl_Obj *query_string_parameters_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, req_dict_ptr, query_string_parameters_key_ptr, &query_string_parameters_ptr)) {
        Tcl_DecrRefCount(query_string_parameters_key_ptr);
        SetResult("get_query_param: error reading queryStringParameters from request_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(query_string_parameters_key_ptr);

    if (query_string_parameters_ptr) {
        // check if "param_name" is part of it and return it
        Tcl_Obj *valuePtr;
        if (TCL_OK != Tcl_DictObjGet(interp, query_string_parameters_ptr, param_name_ptr, &valuePtr)) {
            SetResult("get_query_param: error reading param_name from queryStringParameters");
            return TCL_ERROR;
        }
        if (valuePtr) {
            if (option_multi) {
                Tcl_Obj *listValuePtr = Tcl_NewListObj(0, NULL);
                Tcl_IncrRefCount(listValuePtr);
                if (TCL_OK != Tcl_ListObjAppendElement(interp, listValuePtr, valuePtr)) {
                    Tcl_DecrRefCount(listValuePtr);
                    SetResult("get_query_param: error appending to list");
                    return TCL_ERROR;
                }
                *result_ptr = listValuePtr;
                return TCL_OK;
            } else {
                *result_ptr = valuePtr;
                return TCL_OK;
            }
        }
    }
    *result_ptr = NULL;
    return TCL_OK;
}

int tws_GetQueryParamCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "GetQueryParamCmd\n"));
    CheckArgs(3, 4, 1, "request_dict param_name ?return_list?");

    int option_multi = 0;
    if (objc == 4) {
        if (TCL_OK != Tcl_GetBooleanFromObj(interp, objv[3], &option_multi)) {
            return TCL_ERROR;
        }
    }

    Tcl_Obj *result_ptr;
    if (TCL_OK != tws_GetQueryParam(interp, objv[1], objv[2], option_multi, &result_ptr)) {
        SetResult("get_query_param: error reading param_name");
        return TCL_ERROR;
    }

    if (result_ptr != NULL) {
        Tcl_SetObjResult(interp, result_ptr);
    }

    if (option_multi) {
        Tcl_DecrRefCount(result_ptr);
    }

    return TCL_OK;
}

static int tws_GetPathParam(Tcl_Interp *interp, Tcl_Obj *req_dict_ptr, Tcl_Obj *param_name_ptr, int option_multi, Tcl_Obj **result_ptr) {
    // Check if "pathParameters" exists, check if "param_name" is part of it and return it

    Tcl_Obj *path_parameters_key_ptr = Tcl_NewStringObj("pathParameters", -1);
    Tcl_IncrRefCount(path_parameters_key_ptr);
    Tcl_Obj *path_parameters_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, req_dict_ptr, path_parameters_key_ptr, &path_parameters_ptr)) {
        Tcl_DecrRefCount(path_parameters_key_ptr);
        SetResult("get_path_param: error reading pathParameters from request_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(path_parameters_key_ptr);

    if (path_parameters_ptr) {
        // check if "param_name" is part of it and return it
        Tcl_Obj *valuePtr;
        if (TCL_OK != Tcl_DictObjGet(interp, path_parameters_ptr, param_name_ptr, &valuePtr)) {
            SetResult("get_path_param: error reading param_name from pathParameters");
            return TCL_ERROR;
        }
        if (valuePtr) {
            if (option_multi) {
                Tcl_Obj *listValuePtr = Tcl_NewListObj(0, NULL);
                Tcl_IncrRefCount(listValuePtr);
                if (TCL_OK != Tcl_ListObjAppendElement(interp, listValuePtr, valuePtr)) {
                    Tcl_DecrRefCount(listValuePtr);
                    SetResult("get_path_param: error appending to list");
                    return TCL_ERROR;
                }
                *result_ptr = listValuePtr;
                return TCL_OK;
            } else {
                *result_ptr = valuePtr;
                return TCL_OK;
            }
        }
    }
    *result_ptr = NULL;
    return TCL_OK;
}

int tws_GetPathParamCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "GetPathParamCmd\n"));
    CheckArgs(3, 4, 1, "request_dict param_name ?return_list?");

    int option_multi = 0;
    if (objc == 4) {
        if (TCL_OK != Tcl_GetBooleanFromObj(interp, objv[3], &option_multi)) {
            return TCL_ERROR;
        }
    }

    Tcl_Obj *result_ptr;
    if (TCL_OK != tws_GetPathParam(interp, objv[1], objv[2], option_multi, &result_ptr)) {
        SetResult("get_path_param: error reading param_name from pathParameters");
        return TCL_ERROR;
    }

    if (result_ptr != NULL) {
        Tcl_SetObjResult(interp, result_ptr);
    }

    if (option_multi) {
        Tcl_DecrRefCount(result_ptr);
    }

    return TCL_OK;
}

static int tws_GetHeader(Tcl_Interp *interp, Tcl_Obj *req_dict_ptr, Tcl_Obj *param_name_ptr, int option_multi, Tcl_Obj **result_ptr) {
    // Check request_dict for the following keys:
    //    multiValueHeaders
    //    headers

    // If "multiValueHeaders" exists, check if "header_name" is part of it and return it

    Tcl_Obj *multi_value_headers_key_ptr = Tcl_NewStringObj("multiValueHeaders", -1);
    Tcl_IncrRefCount(multi_value_headers_key_ptr);
    Tcl_Obj *multi_value_headers_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, req_dict_ptr, multi_value_headers_key_ptr, &multi_value_headers_ptr)) {
        Tcl_DecrRefCount(multi_value_headers_key_ptr);
        SetResult("get_header: error reading multiValueHeaders from request_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(multi_value_headers_key_ptr);

    if (multi_value_headers_ptr) {
        // check if "header_name" is part of it and return it
        Tcl_Obj *listValuePtr;
        if (TCL_OK != Tcl_DictObjGet(interp, multi_value_headers_ptr, param_name_ptr, &listValuePtr)) {
            SetResult("get_header: error reading param_name from multiValueHeaders");
            return TCL_ERROR;
        }
        if (listValuePtr) {
            Tcl_IncrRefCount(listValuePtr);
            *result_ptr = listValuePtr;
            return TCL_OK;
        }
    }

    // If "headers" exists, check if "header_name" is part of it and return it

    Tcl_Obj *headers_key_ptr = Tcl_NewStringObj("headers", -1);
    Tcl_IncrRefCount(headers_key_ptr);
    Tcl_Obj *headers_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, req_dict_ptr, headers_key_ptr, &headers_ptr)) {
        Tcl_DecrRefCount(headers_key_ptr);
        SetResult("get_header: error reading headers from request_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(headers_key_ptr);

    if (headers_ptr) {
        // check if "header_name" is part of it and return it
        Tcl_Obj *valuePtr;
        if (TCL_OK != Tcl_DictObjGet(interp, headers_ptr, param_name_ptr, &valuePtr)) {
            SetResult("get_header: error reading param_name from headers");
            return TCL_ERROR;
        }
        if (valuePtr) {
            if (option_multi) {
                Tcl_Obj *listValuePtr = Tcl_NewListObj(0, NULL);
                Tcl_IncrRefCount(listValuePtr);
                if (TCL_OK != Tcl_ListObjAppendElement(interp, listValuePtr, valuePtr)) {
                    Tcl_DecrRefCount(listValuePtr);
                    SetResult("get_header: error appending to list");
                    return TCL_ERROR;
                }
                *result_ptr = listValuePtr;
                return TCL_OK;
            } else {
                *result_ptr = valuePtr;
                return TCL_OK;
            }
        }
    }

    *result_ptr = NULL;
    return TCL_OK;
}

int tws_GetHeaderCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "GetPathParamCmd\n"));
    CheckArgs(3, 4, 1, "request_dict header_name ?return_list?");

    int option_multi = 0;
    if (objc == 4) {
        if (TCL_OK != Tcl_GetBooleanFromObj(interp, objv[3], &option_multi)) {
            return TCL_ERROR;
        }
    }

    Tcl_Obj *result_ptr;
    if (TCL_OK != tws_GetHeader(interp, objv[1], objv[2], option_multi, &result_ptr)) {
        SetResult("get_header: error reading param_name from headers");
        return TCL_ERROR;
    }

    if (result_ptr != NULL) {
        Tcl_SetObjResult(interp, result_ptr);
    }

    if (option_multi) {
        Tcl_DecrRefCount(result_ptr);
    }

    return TCL_OK;
}

int tws_GetParamCmd(ClientData clientData, Tcl_Interp *interp, int incoming_objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "GetParamCmd\n"));

    int option_multi = 0;
    int option_query = 0;
    int option_path = 0;
    int option_header = 0;
    Tcl_ArgvInfo ArgTable[] = {
            {TCL_ARGV_CONSTANT, "-return_list", INT2PTR(1), &option_multi,  "return a list of values"},
            {TCL_ARGV_CONSTANT, "-from_query",  INT2PTR(1), &option_query,  "return query parameter"},
            {TCL_ARGV_CONSTANT, "-from_path",   INT2PTR(1), &option_path,   "return path parameter"},
            {TCL_ARGV_CONSTANT, "-from_header", INT2PTR(1), &option_header, "return header value"},
            {TCL_ARGV_END, NULL,                NULL, NULL, NULL}
    };

    Tcl_Obj **remObjv;
    Tcl_Size objc = incoming_objc;
    Tcl_ParseArgsObjv(interp, ArgTable, &objc, objv, &remObjv);

    if ((objc < 3) || (objc > 3)) {
        ckfree(remObjv);
        Tcl_WrongNumArgs(interp, 1, remObjv, "request_dict param_name");
        return TCL_ERROR;
    }

    int check_all_p = !option_path & !option_query & !option_header;

    Tcl_Obj *result_ptr = NULL;

    if (check_all_p || option_path) {
        if (TCL_OK == tws_GetPathParam(interp, remObjv[1], remObjv[2], option_multi, &result_ptr) && result_ptr != NULL) {
            ckfree(remObjv);
            Tcl_SetObjResult(interp, result_ptr);
            return TCL_OK;
        }
    }

    if (check_all_p || option_query) {
        if (TCL_OK == tws_GetQueryParam(interp, remObjv[1], remObjv[2], option_multi, &result_ptr) && result_ptr != NULL) {
            ckfree(remObjv);
            Tcl_SetObjResult(interp, result_ptr);
            return TCL_OK;
        }
    }

    if (check_all_p || option_header) {
        if (TCL_OK == tws_GetHeader(interp, remObjv[1], remObjv[2], option_multi, &result_ptr) && result_ptr != NULL) {
            ckfree(remObjv);
            Tcl_SetObjResult(interp, result_ptr);
            return TCL_OK;
        }
    }

    ckfree(remObjv);
    return TCL_OK;
}

int tws_IpV6ToIpV4Cmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "IpV6ToIpV4Cmd\n"));
    CheckArgs(2, 2, 1, "ipv6_address");

    // check if the input is a valid IPv6 address and whether it can be mapped to IPv4
    const char *ipv6_address = Tcl_GetString(objv[1]);
    struct in6_addr addr;
    if (inet_pton(AF_INET6, ipv6_address, &addr) != 1) {
        SetResult("to_ipv4: invalid IPv6 address");
        return TCL_ERROR;
    }

    // check if the address can be mapped to IPv4
    struct in_addr addr4;
    if (IN6_IS_ADDR_V4MAPPED(&addr)) {
        memcpy(&addr4, addr.s6_addr + 12, 4);
    } else {
        return TCL_OK;
    }

    // convert the IPv4 address to a string
    char ip_address_v4[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr4, ip_address_v4, INET_ADDRSTRLEN) == NULL) {
        SetResult("to_ipv4: error converting IPv4 address to string");
        return TCL_ERROR;
    }

    SetResult(ip_address_v4);
    return TCL_OK;
}

int tws_ReturnResponseCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "ReturnResponseCmd\n"));
    CheckArgs(3, 4, 1, "conn_handle response_dict ?encoding?");

    const char *conn_handle = Tcl_GetString(objv[1]);
    tws_conn_t *conn = tws_GetInternalFromConnName(conn_handle);
    if (!conn) {
        SetResult("return_response: conn handle not found");
        return TCL_ERROR;
    }

    const char *encoding_name = "utf-8";
    if (objc == 3) {
        Tcl_Size encoding_name_length;
        encoding_name = Tcl_GetStringFromObj(objv[3], &encoding_name_length);
    }

    if (TCL_OK != tws_ReturnConn(interp, conn, objv[2])) {
        return TCL_ERROR;
    }

    return TCL_OK;
}

static int tws_HandleBreakLoopInMainThread(Tcl_Event *evPtr, int flags) {
    signal_flag = 1;
    return 1;
}

void tws_QueueBreakLoopEvent() {
    Tcl_Event *evPtr = (Tcl_Event *) Tcl_Alloc(sizeof(Tcl_Event));
    evPtr->proc = tws_HandleBreakLoopInMainThread;
    Tcl_QueueEvent(evPtr, TCL_QUEUE_TAIL);
    Tcl_ThreadAlert(Tcl_GetCurrentThread());
}

void tws_SignalHandler(int signum) {
    if (signum == SIGTERM || signum == SIGINT) {
        fprintf(stderr, "Caught signal: %s\n", signum == SIGTERM ? "SIGTERM" : "SIGINT");
        if (!signal_flag) {
            tws_QueueBreakLoopEvent();
        }
    }
}

static int tws_WaitSignalCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "VarWaitCmd\n"));
    CheckArgs(1, 1, 1, "");

    signal_flag = 0;
    signal(SIGTERM, tws_SignalHandler);
    signal(SIGINT, tws_SignalHandler);

    do {
        Tcl_DoOneEvent(TCL_ALL_EVENTS);
    } while (!signal_flag);

    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);

    return TCL_OK;
}

Tcl_Obj *tws_GetConfigDict() {
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(tws_GetThreadDataKey(), sizeof(tws_thread_data_t));
    return dataPtr->config_dict_ptr;
}

static int tws_GetRootdirCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "GetRootdirCmd\n"));
    CheckArgs(1, 2, 1, "");

    Tcl_Obj *config_dict_ptr = tws_GetConfigDict();
    if (config_dict_ptr == NULL) {
        SetResult("get_rootdir: config_dict not found");
        return TCL_ERROR;
    }

    Tcl_Obj *rootdir_key_ptr = Tcl_NewStringObj("rootdir", -1);
    Tcl_IncrRefCount(rootdir_key_ptr);
    Tcl_Obj *rootdir_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, config_dict_ptr, rootdir_key_ptr, &rootdir_ptr)) {
        Tcl_DecrRefCount(rootdir_key_ptr);
        SetResult("get_rootdir: error reading rootdir from config_dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(rootdir_key_ptr);

    if (rootdir_ptr == NULL) {
        SetResult("get_rootdir: rootdir not found in config_dict");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_DuplicateObj(rootdir_ptr));
    return TCL_OK;
}

static int tws_GetConfigDictCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "GetConfigDictCmd\n"));
    CheckArgs(1, 1, 1, "");

    Tcl_Obj *config_dict_ptr = tws_GetConfigDict();
    if (config_dict_ptr == NULL) {
        SetResult("get_rootdir: config_dict not found");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_DuplicateObj(config_dict_ptr));
    return TCL_OK;
}

static void tws_ExitHandler(ClientData unused) {
    DBG(fprintf(stderr, "Exit Handler: start\n"));
    tws_DeleteServerNameHT();
    tws_DeleteConnNameHT();
    tws_DeleteHostNameHT();
    tws_DeleteRouterNameHT();

    DBG(fprintf(stderr, "Exit Handler: done\n"));
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

        Tcl_CreateExitHandler(tws_ExitHandler, NULL);
        tws_ModuleInitialized = 1;
    }
}

#if TCL_MAJOR_VERSION > 8
#define MIN_VERSION "9.0"
#else
#define MIN_VERSION "8.6"
#endif

int Twebserver_Init(Tcl_Interp *interp) {

    if (Tcl_InitStubs(interp, MIN_VERSION, 0) == NULL) {
        SetResult("Unable to initialize Tcl stubs");
        return TCL_ERROR;
    }

    tws_InitModule();

    Tcl_CreateNamespace(interp, "::twebserver", NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::create_server", tws_CreateServerCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::destroy_server", tws_DestroyServerCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::listen_server", tws_ListenCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::add_context", tws_AddContextCmd, NULL, NULL);

    Tcl_CreateObjCommand(interp, "::twebserver::wait_signal", tws_WaitSignalCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::get_rootdir", tws_GetRootdirCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::get_config_dict", tws_GetConfigDictCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::info_conn", tws_InfoConnCmd, NULL, NULL);

    Tcl_CreateObjCommand(interp, "::twebserver::encode_uri_component", tws_EncodeURIComponentCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::decode_uri_component", tws_DecodeURIComponentCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::encode_query", tws_EncodeQueryCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::base64_encode", tws_Base64EncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::base64_decode", tws_Base64DecodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::hex_encode", tws_HexEncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::hex_decode", tws_HexDecodeCmd, NULL, NULL);

    Tcl_CreateObjCommand(interp, "::twebserver::create_router", tws_CreateRouterCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::add_route", tws_AddRouteCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::info_routes", tws_InfoRoutesCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::add_middleware", tws_AddMiddlewareCmd, NULL, NULL);

    Tcl_CreateObjCommand(interp, "::twebserver::parse_cookie", tws_ParseCookieCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::add_header", tws_AddHeaderCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::add_cookie", tws_AddCookieCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::build_response", tws_BuildResponseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::build_redirect", tws_BuildRedirectCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::parse_query", tws_ParseQueryCmd, NULL, NULL);

    Tcl_CreateObjCommand(interp, "::twebserver::random_bytes", tws_RandomBytesCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::sha1", tws_Sha1Cmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::sha256", tws_Sha256Cmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::sha512", tws_Sha512Cmd, NULL, NULL);

    Tcl_CreateObjCommand(interp, "::twebserver::get_form", tws_GetFormCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::get_header", tws_GetHeaderCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::get_query_param", tws_GetQueryParamCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::get_path_param", tws_GetPathParamCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::twebserver::get_param", tws_GetParamCmd, NULL, NULL);

    Tcl_CreateObjCommand(interp, "::twebserver::ipv6_to_ipv4", tws_IpV6ToIpV4Cmd, NULL, NULL);

    Tcl_CreateObjCommand(interp, "::twebserver::return_response", tws_ReturnResponseCmd, NULL, NULL);

    return Tcl_PkgProvide(interp, "twebserver", XSTR(VERSION));
}
