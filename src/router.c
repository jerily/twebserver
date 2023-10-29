/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#include "common.h"
#include "conn.h"
#include "router.h"
#include "path_regexp/path_regexp.h"
#include "request.h"
#include <string.h>

enum {
    ROUTE_TYPE_EXACT,
    ROUTE_TYPE_REGEXP
};

static int tws_MatchRegExpRoute(Tcl_Interp *interp, tws_route_t *route_ptr, Tcl_Obj *path_ptr, Tcl_Obj *requestDictPtr,
                                int *matched) {

    int cflags = TCL_REG_ADVANCED;
    if (route_ptr->option_nocase) {
        cflags |= TCL_REG_NOCASE;
    }
    Tcl_Obj *patObj = Tcl_NewStringObj(route_ptr->pattern, -1);
    Tcl_IncrRefCount(patObj);
    Tcl_RegExp regexp = Tcl_GetRegExpFromObj(interp, patObj, cflags);
    Tcl_DecrRefCount(patObj);
    if (regexp == NULL) {
        SetResult("MatchRoute: regexp compile failed");
        return TCL_ERROR;
    }

    // nmatches: The number of matching subexpressions that should be remembered for later use.
    // If this value is 0, then no subexpression match information will be computed.
    // If the value is -1, then all of the matching subexpressions will be remembered.
    // Any other value will be taken as the maximum number of subexpressions to remember.

    if (Tcl_RegExpExecObj(interp, regexp, path_ptr, 0, -1, 0) == 1) {
        *matched = 1;

        DBG(fprintf(stderr, "matched pattern: %s\n", route_ptr->pattern));

        int keys_objc;
        Tcl_Obj **keys_objv;
        Tcl_ListObjGetElements(interp, route_ptr->keys, &keys_objc, &keys_objv);
        Tcl_Obj *pathParametersDictPtr = Tcl_NewDictObj();
        const char *start;
        const char *end;
        for (int i = 0; i < keys_objc; i++) {
            Tcl_RegExpRange(regexp, i + 1, &start, &end);
            Tcl_Obj *key_ptr = keys_objv[i];
            Tcl_Obj *value_ptr = Tcl_NewStringObj(start, end - start);

            DBG(fprintf(stderr, "key: %s, value: %s\n", Tcl_GetString(key_ptr), Tcl_GetString(value_ptr)));

            if (TCL_OK != Tcl_DictObjPut(interp, pathParametersDictPtr, key_ptr, value_ptr)) {
                SetResult("MatchRoute: dict put failed");
                return TCL_ERROR;
            }
        }

        Tcl_Obj *pathParametersKeyPtr = Tcl_NewStringObj("pathParameters", -1);
        if (TCL_OK != Tcl_DictObjPut(interp, requestDictPtr, pathParametersKeyPtr, pathParametersDictPtr)) {
            SetResult("MatchRoute: dict put failed");
            return TCL_ERROR;
        }
    } else {
        *matched = 0;
    }
    return TCL_OK;
}

static int tws_MatchExactRoute(Tcl_Interp *interp, tws_route_t *route_ptr, Tcl_Obj *path_ptr, int *matched) {
    int path_len;
    char *path = Tcl_GetStringFromObj(path_ptr, &path_len);

    if (route_ptr->option_nocase) {
        path_len = Tcl_UtfToLower(path);
    }

    if (route_ptr->option_prefix) {
        *matched = (path_len >= route_ptr->path_len
                    && strncmp(path, route_ptr->path, route_ptr->path_len) == 0);
    } else {
        *matched = (path_len == route_ptr->path_len
                    && strncmp(path, route_ptr->path, path_len) == 0);
    }
    return TCL_OK;
}

static int tws_MatchRoute(Tcl_Interp *interp, tws_route_t *route_ptr, Tcl_Obj *requestDictPtr, int *matched) {
    Tcl_Obj *http_method_key_ptr = Tcl_NewStringObj("httpMethod", -1);
    Tcl_IncrRefCount(http_method_key_ptr);
    Tcl_Obj *http_method_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, requestDictPtr, http_method_key_ptr, &http_method_ptr)) {
        Tcl_DecrRefCount(http_method_key_ptr);
        SetResult("MatchRoute: dict get failed");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(http_method_key_ptr);

    if (!http_method_ptr) {
        *matched = 0;
        return TCL_OK;
    }

    int http_method_len;
    const char *http_method = Tcl_GetStringFromObj(http_method_ptr, &http_method_len);

    Tcl_Obj *path_key_ptr = Tcl_NewStringObj("path", -1);
    Tcl_IncrRefCount(path_key_ptr);
    Tcl_Obj *path_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, requestDictPtr, path_key_ptr, &path_ptr)) {
        Tcl_DecrRefCount(path_key_ptr);
        SetResult("MatchRoute: dict get failed");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(path_key_ptr);

    if (!path_ptr) {
        *matched = 0;
        return TCL_OK;
    }

    if (http_method_len == route_ptr->http_method_len
        && strncmp(http_method, route_ptr->http_method, route_ptr->http_method_len) == 0) {

        if (route_ptr->fast_slash || route_ptr->fast_star) {
            *matched = 1;
            return TCL_OK;
        }

        if (route_ptr->type == ROUTE_TYPE_EXACT) {
            if (TCL_OK != tws_MatchExactRoute(interp, route_ptr, path_ptr, matched)) {
                SetResult("MatchRoute: match_exact_route failed");
                return TCL_ERROR;
            }
        } else {
            if (TCL_OK != tws_MatchRegExpRoute(interp, route_ptr, path_ptr, requestDictPtr, matched)) {
                SetResult("MatchRoute: match_regexp_route failed");
                return TCL_ERROR;
            }
        }

    } else {
        *matched = 0;
    }

    return TCL_OK;
}

static int tws_EvalRoute(Tcl_Interp *interp, tws_route_t *route_ptr, Tcl_Obj *ctx_dict_ptr, Tcl_Obj *req_dict_ptr) {

    Tcl_Obj *proc_name_ptr = Tcl_NewStringObj(route_ptr->proc_name, -1);
    Tcl_IncrRefCount(proc_name_ptr);
    Tcl_Obj *const proc_objv[] = {proc_name_ptr, ctx_dict_ptr, req_dict_ptr};
    if (TCL_OK != Tcl_EvalObjv(interp, 3, proc_objv, TCL_EVAL_GLOBAL)) {
        Tcl_DecrRefCount(proc_name_ptr);
//        SetResult("router_process_conn: eval failed");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(proc_name_ptr);
    return TCL_OK;
}

static int
tws_ReturnError(Tcl_Interp *interp, tws_conn_t *conn, int status_code, const char *error_text, Tcl_Encoding encoding) {
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

static int tws_DoRouting(Tcl_Interp *interp, tws_router_t *router_ptr, tws_conn_t *conn, Tcl_Obj *req_dict_ptr) {
    Tcl_Encoding encoding = Tcl_GetEncoding(interp, "utf-8");

    Tcl_Obj *ctx_dict_ptr = Tcl_NewDictObj();
    Tcl_IncrRefCount(ctx_dict_ptr);

    Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("router", -1), Tcl_NewStringObj(router_ptr->handle, -1));
    Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("conn", -1), Tcl_NewStringObj(conn->conn_handle, -1));
    Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("addr", -1), Tcl_NewStringObj(conn->client_ip, -1));
    Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("port", -1), Tcl_NewIntObj(conn->server->accept_ctx->port));

    tws_route_t *route_ptr = router_ptr->firstRoutePtr;
    while (route_ptr != NULL) {
        int matched = 0;
        if (TCL_OK != tws_MatchRoute(interp, route_ptr, req_dict_ptr, &matched)) {
            Tcl_DecrRefCount(ctx_dict_ptr);
            Tcl_DecrRefCount(req_dict_ptr);
            SetResult("router_process_conn: match_route failed");
            return TCL_ERROR;
        }

        if (matched) {
            Tcl_ResetResult(interp);

            // traverse middleware enter procs
            tws_middleware_t *prev_middleware_ptr = NULL;
            tws_middleware_t *middleware_ptr = router_ptr->firstMiddlewarePtr;
            while (middleware_ptr != NULL) {
                if (middleware_ptr->enter_proc_ptr) {
                    Tcl_Obj *const proc_objv[] = {middleware_ptr->enter_proc_ptr, ctx_dict_ptr, req_dict_ptr};
                    if (TCL_OK != Tcl_EvalObjv(interp, 3, proc_objv, TCL_EVAL_GLOBAL)) {
                        if (TCL_OK != tws_ReturnError(interp, conn, 500, "Internal Server Error", encoding)) {
                            tws_CloseConn(conn, 1);
                            Tcl_DecrRefCount(ctx_dict_ptr);
                            Tcl_DecrRefCount(req_dict_ptr);
                            SetResult("router_process_conn: return_error failed");
                            return TCL_ERROR;
                        }
                        tws_CloseConn(conn, 1);
                        Tcl_DecrRefCount(ctx_dict_ptr);
                        Tcl_DecrRefCount(req_dict_ptr);
                        // SetResult("router_process_conn: enter proc eval failed");
                        return TCL_ERROR;
                    }
                    Tcl_DecrRefCount(req_dict_ptr);
                    req_dict_ptr = Tcl_GetObjResult(interp);
                    Tcl_IncrRefCount(req_dict_ptr);
                }
                prev_middleware_ptr = middleware_ptr;
                middleware_ptr = middleware_ptr->nextPtr;
            }

            DBG(fprintf(stderr, "req: %s\n", Tcl_GetString(req_dict_ptr)));

            // eval route proc
            if (TCL_OK != tws_EvalRoute(interp, route_ptr, ctx_dict_ptr, req_dict_ptr)) {
                DBG(fprintf(stderr, "router_process_conn: eval route failed path: %s\n", route_ptr->path));
                if (TCL_OK != tws_ReturnError(interp, conn, 500, "Internal Server Error", encoding)) {
                    tws_CloseConn(conn, 1);
                    Tcl_DecrRefCount(ctx_dict_ptr);
                    Tcl_DecrRefCount(req_dict_ptr);
                    SetResult("router_process_conn: return_error failed");
                    return TCL_ERROR;
                }
                tws_CloseConn(conn, 1);
                Tcl_DecrRefCount(ctx_dict_ptr);
                Tcl_DecrRefCount(req_dict_ptr);
//                SetResult("router_process_conn: eval route failed");
                return TCL_ERROR;
            }

            Tcl_Obj *res_dict_ptr = Tcl_GetObjResult(interp);
            Tcl_IncrRefCount(res_dict_ptr);

            // traverse middleware leave procs in reverse order
            middleware_ptr = prev_middleware_ptr;
            while (middleware_ptr != NULL) {
                if (middleware_ptr->leave_proc_ptr) {
                    Tcl_Obj *const proc_objv[] = {middleware_ptr->leave_proc_ptr, ctx_dict_ptr, req_dict_ptr,
                                                  res_dict_ptr};
                    if (TCL_OK != Tcl_EvalObjv(interp, 4, proc_objv, TCL_EVAL_GLOBAL)) {
                        if (TCL_OK != tws_ReturnError(interp, conn, 500, "Internal Server Error", encoding)) {
                            tws_CloseConn(conn, 1);
                            Tcl_DecrRefCount(ctx_dict_ptr);
                            Tcl_DecrRefCount(req_dict_ptr);
                            Tcl_DecrRefCount(res_dict_ptr);
                            SetResult("router_process_conn: return_error failed");
                            return TCL_ERROR;
                        }
                        tws_CloseConn(conn, 1);
                        Tcl_DecrRefCount(ctx_dict_ptr);
                        Tcl_DecrRefCount(req_dict_ptr);
                        Tcl_DecrRefCount(res_dict_ptr);
                        // SetResult("router_process_conn: leave proc eval failed");
                        return TCL_ERROR;
                    }
                    Tcl_DecrRefCount(res_dict_ptr);
                    res_dict_ptr = Tcl_GetObjResult(interp);
                    Tcl_IncrRefCount(res_dict_ptr);
                }
                middleware_ptr = middleware_ptr->prevPtr;
            }

            // return response
            if (TCL_OK != tws_ReturnConn(interp, conn, res_dict_ptr, encoding)) {
                if (TCL_OK != tws_ReturnError(interp, conn, 500, "Internal Server Error", encoding)) {
                    tws_CloseConn(conn, 1);
                    Tcl_DecrRefCount(ctx_dict_ptr);
                    Tcl_DecrRefCount(req_dict_ptr);
                    Tcl_DecrRefCount(res_dict_ptr);
                    SetResult("router_process_conn: return_error failed");
                    return TCL_ERROR;
                }
                tws_CloseConn(conn, 1);
                Tcl_DecrRefCount(ctx_dict_ptr);
                Tcl_DecrRefCount(req_dict_ptr);
                Tcl_DecrRefCount(res_dict_ptr);
//                SetResult("router_process_conn: return_conn failed");
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(res_dict_ptr);
            break; // break out of while loop to decr ref counts and close conn
        }
        route_ptr = route_ptr->nextPtr;
    }
    Tcl_DecrRefCount(ctx_dict_ptr);
    Tcl_DecrRefCount(req_dict_ptr);

    if (TCL_OK != tws_CloseConn(conn, 0)) {
        SetResult("router_process_conn: close_conn failed");
        return TCL_ERROR;
    }
    DBG(fprintf(stderr, "------------done\n"));

    return TCL_OK;
}

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
            if (TCL_OK != Tcl_GetIntFromObj(interp, contentLengthPtr, &conn->content_length)) {
                Tcl_DecrRefCount(req_dict_ptr);
                return TCL_ERROR;
            }
        }

        if (conn->server->keepalive) {
            if (TCL_OK != tws_ParseConnectionKeepalive(interp, headersPtr, &conn->keepalive)) {
                Tcl_DecrRefCount(req_dict_ptr);
                return TCL_ERROR;
            }
        }

        if (conn->server->gzip) {
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
        } else {
            if (TCL_OK !=
                Tcl_DictObjPut(interp, req_dict_ptr, Tcl_NewStringObj("isBase64Encoded", -1), Tcl_NewBooleanObj(0))) {
                goto handle_error;
            }
            if (TCL_OK !=
                Tcl_DictObjPut(interp, req_dict_ptr, Tcl_NewStringObj("body", -1), Tcl_NewStringObj("", -1))) {
                goto handle_error;
            }
        }
    }

    return TCL_OK;
    handle_error:
    return TCL_ERROR;
}

static int tws_ShouldParseTopPart(tws_conn_t *conn) {
    return conn->requestDictPtr == NULL && Tcl_DStringLength(&conn->ds) > 0;
}

static int tws_ShouldParseBottomPart(tws_conn_t *conn) {
    return conn->content_length > 0;
}

static int tws_HandleRecv(tws_router_t *router_ptr, tws_conn_t *conn) {
    DBG(fprintf(stderr, "HandleRecv: %s\n", conn->conn_handle));

    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(conn->dataKeyPtr, sizeof(tws_thread_data_t));

    if (tws_ShouldParseTopPart(conn)) {
        DBG(fprintf(stderr, "parse top part after deferring reqdictptr=%p\n", conn->requestDictPtr));
        // case when we have read as much as we could with deferring
        if (TCL_OK != tws_ParseTopPart(dataPtr->interp, conn)) {
            fprintf(stderr, "ParseTopPart failed (before rubicon): %s\n",
                    Tcl_GetString(Tcl_GetObjResult(dataPtr->interp)));
            return 1;
        }
    }

    int remaining_unprocessed = Tcl_DStringLength(&conn->ds) - conn->offset;
    int ret = tws_ReadConnAsync(dataPtr->interp, conn, &conn->ds, conn->content_length - remaining_unprocessed);
    if (TWS_AGAIN == ret) {
        if (conn->offset == 0) {
            DBG(fprintf(stderr, "retry dslen=%d reqdictptr=%p\n", Tcl_DStringLength(&conn->ds), conn->requestDictPtr));
            return 0;
        }
    } else if (TWS_ERROR == ret) {
        fprintf(stderr, "err\n");
        if (conn->requestDictPtr != NULL) {
            Tcl_DecrRefCount(conn->requestDictPtr);
            conn->requestDictPtr = NULL;
        }
        return 1;
    }

    DBG(fprintf(stderr, "rubicon\n"));

    if (tws_ShouldParseTopPart(conn)) {
        // case when we have read as much as we could without deferring
        if (TCL_OK != tws_ParseTopPart(dataPtr->interp, conn)) {
            fprintf(stderr, "ParseTopPart failed (after rubicon): %s\n",
                    Tcl_GetString(Tcl_GetObjResult(dataPtr->interp)));
            return 1;
        }
    }

    Tcl_Obj *req_dict_ptr = conn->requestDictPtr;
    conn->requestDictPtr = NULL;

    if (tws_ShouldParseBottomPart(conn)) {
        if (TCL_OK != tws_ParseBottomPart(dataPtr->interp, conn, req_dict_ptr)) {
            fprintf(stderr, "ParseBottomPart failed: %s\n", Tcl_GetString(Tcl_GetObjResult(dataPtr->interp)));
            Tcl_DecrRefCount(req_dict_ptr);
            return 1;
        }
    }

    // no need to decr ref count of req_dict_ptr because it is already decr ref counted in DoRouting
    if (TCL_OK != tws_DoRouting(dataPtr->interp, router_ptr, conn, req_dict_ptr)) {
        fprintf(stderr, "DoRouting failed: %s\n", Tcl_GetString(Tcl_GetObjResult(dataPtr->interp)));
        return 1;
    }

    DBG(fprintf(stderr, "DoRouting done refCount: %d\n", req_dict_ptr->refCount));
    return 1;
}

static int tws_HandleRecvEventInThread(Tcl_Event *evPtr, int flags) {
    tws_router_event_t *routerEvPtr = (tws_router_event_t *) evPtr;
    tws_router_t *router = (tws_router_t *) routerEvPtr->routerClientData;
    tws_conn_t *conn = (tws_conn_t *) routerEvPtr->connClientData;
    DBG(fprintf(stderr, "HandleRecvEventInThread: %s\n", conn->conn_handle));
    int result = tws_HandleRecv(router, conn);
    if (!result) {
        Tcl_ThreadAlert(conn->threadId);
    }
    return result;
}

static void tws_ThreadQueueRecvEvent(tws_router_t *router_ptr, tws_conn_t *conn) {
    DBG(fprintf(stderr, "ThreadQueueRecvEvent - threadId: %p\n", conn->threadId));
    tws_router_event_t *routerEvPtr = (tws_router_event_t *) Tcl_Alloc(sizeof(tws_router_event_t));
    routerEvPtr->proc = tws_HandleRecvEventInThread;
    routerEvPtr->nextPtr = NULL;
    routerEvPtr->routerClientData = (ClientData *) router_ptr;
    routerEvPtr->connClientData = (ClientData *) conn;
    Tcl_QueueEvent((Tcl_Event *) routerEvPtr, TCL_QUEUE_TAIL);
    Tcl_ThreadAlert(conn->threadId);
    DBG(fprintf(stderr, "ThreadQueueRecvEvent done - threadId: %p\n", conn->threadId));
}

static int tws_RouterProcessConnCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "RouterProcessConnCmd\n"));
    CheckArgs(4, 4, 1, "conn_handle addr port");

    tws_router_t *router_ptr = (tws_router_t *) clientData;

    const char *conn_handle = Tcl_GetString(objv[1]);
    tws_conn_t *conn = tws_GetInternalFromConnName(conn_handle);
    if (!conn) {
        SetResult("router_process_conn: conn handle not found");
        return TCL_ERROR;
    }

    tws_ThreadQueueRecvEvent(router_ptr, conn);

    return TCL_OK;
}

int tws_CreateRouterCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "CreateCmd\n"));
    CheckArgs(1, 1, 1, "");

    tws_router_t *router_ptr = (tws_router_t *) Tcl_Alloc(sizeof(tws_router_t));
    if (!router_ptr) {
        SetResult("create_router: memory alloc failed");
        return TCL_ERROR;
    }
    router_ptr->firstRoutePtr = NULL;
    router_ptr->lastRoutePtr = NULL;
    router_ptr->firstMiddlewarePtr = NULL;
    router_ptr->lastMiddlewarePtr = NULL;

    CMD_ROUTER_NAME(router_ptr->handle, router_ptr);
    tws_RegisterRouterName(router_ptr->handle, router_ptr);
    DBG(fprintf(stderr, "creating obj cmd\n"));
    Tcl_CreateObjCommand(interp, router_ptr->handle, tws_RouterProcessConnCmd, (ClientData) router_ptr, NULL);
    DBG(fprintf(stderr, "done creating obj cmd\n"));

    SetResult(router_ptr->handle);
    return TCL_OK;

}

int tws_AddRouteCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AddRouteCmd\n"));

    int option_prefix = 0;
    int option_nocase = 0;
    int option_strict = 0;
    Tcl_ArgvInfo ArgTable[] = {
            {TCL_ARGV_CONSTANT, "-prefix", INT2PTR(1), &option_prefix, "prefix matching"},
            {TCL_ARGV_CONSTANT, "-nocase", INT2PTR(1), &option_nocase, "case insensitive"},
            {TCL_ARGV_CONSTANT, "-strict", INT2PTR(1), &option_strict, "strict matching"},
            {TCL_ARGV_END, NULL,           NULL, NULL, NULL}
    };
    Tcl_Obj **remObjv;
    Tcl_ParseArgsObjv(interp, ArgTable, &objc, objv, &remObjv);

    if ((objc < 5) || (objc > 5)) {
        Tcl_WrongNumArgs(interp, 1, remObjv, "router_handle http_method path proc_name");
        return TCL_ERROR;
    }

    if (option_prefix && option_strict) {
        SetResult("add_route: option -prefix and -strict are mutually exclusive");
        return TCL_ERROR;
    }

    tws_router_t *router_ptr = tws_GetInternalFromRouterName(Tcl_GetString(remObjv[1]));
    if (!router_ptr) {
        SetResult("add_route: router handle not found");
        return TCL_ERROR;
    }
    int http_method_len;
    const char *http_method = Tcl_GetStringFromObj(remObjv[2], &http_method_len);
    int path_len;
    const char *path = Tcl_GetStringFromObj(remObjv[3], &path_len);
    int proc_name_len;
    const char *proc_name = Tcl_GetStringFromObj(remObjv[4], &proc_name_len);

    tws_route_t *route_ptr = (tws_route_t *) Tcl_Alloc(sizeof(tws_route_t));
    if (!route_ptr) {
        SetResult("add_route: memory alloc failed");
        return TCL_ERROR;
    }
    route_ptr->http_method_len = http_method_len;
    route_ptr->path_len = path_len;
    route_ptr->proc_name_len = proc_name_len;

    memcpy(route_ptr->http_method, http_method, http_method_len);
    route_ptr->http_method[http_method_len] = '\0';
    memcpy(route_ptr->path, path, path_len);
    route_ptr->path[path_len] = '\0';
    memcpy(route_ptr->proc_name, proc_name, proc_name_len);
    route_ptr->proc_name[proc_name_len] = '\0';
    route_ptr->nextPtr = NULL;
    route_ptr->keys = NULL;
    route_ptr->pattern = NULL;

    route_ptr->option_prefix = option_prefix;
    route_ptr->option_nocase = option_nocase;
    route_ptr->option_strict = option_strict;
    route_ptr->fast_star = path_len == 1 && path[0] == '*';
    route_ptr->fast_slash = path_len == 1 && path[0] == '/' && option_prefix;

    if (!route_ptr->fast_star && !route_ptr->fast_slash) {
        const char *p = strpbrk(route_ptr->path, ".+*?=^!:${}()[]|");
        if (p != NULL) {
            route_ptr->type = ROUTE_TYPE_REGEXP;

            int flags = 0;
            flags |= START_MATCH;
            if (!option_prefix) {
                flags |= END_MATCH;
            }
            if (option_nocase) {
                flags |= NOCASE_MATCH;
            }
            if (option_strict) {
                flags |= STRICT_MATCH;
            }

            if (TCL_OK != tws_PathToRegExp(interp, path, path_len, flags, &route_ptr->keys, &route_ptr->pattern)) {
                SetResult("add_route: path_to_regexp failed");
                return TCL_ERROR;
            }
        } else {
            route_ptr->type = ROUTE_TYPE_EXACT;
            if (option_nocase) {
                // Changes every UTF-8 character in str to lower-case
                // Because changing the case of a character may change its size,
                // the byte offset of each character in the resulting string may differ from its original location.
                // Tcl_UtfToLower writes a null byte at the end of the converted string.
                // Tcl_UtfToLower returns the new length of the string in bytes.
                // This new length is guaranteed to be no longer than the original string length.
                route_ptr->path_len = Tcl_UtfToLower(route_ptr->path);
            }
        }
    }

    if (router_ptr->firstRoutePtr == NULL) {
        router_ptr->firstRoutePtr = route_ptr;
        router_ptr->lastRoutePtr = route_ptr;
    } else {
        router_ptr->lastRoutePtr->nextPtr = route_ptr;
        router_ptr->lastRoutePtr = route_ptr;
    }

    return TCL_OK;
}

int tws_InfoRoutesCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AddRouteCmd\n"));
    CheckArgs(2, 2, 1, "router_handle");
    tws_router_t *router_ptr = tws_GetInternalFromRouterName(Tcl_GetString(objv[1]));
    if (!router_ptr) {
        SetResult("info_routes: router handle not found");
        return TCL_ERROR;
    }

    Tcl_Obj *result_ptr = Tcl_NewListObj(0, NULL);
    tws_route_t *route_ptr = router_ptr->firstRoutePtr;
    while (route_ptr != NULL) {
        Tcl_Obj *route_dict_ptr = Tcl_NewDictObj();
        Tcl_Obj *http_method_ptr = Tcl_NewStringObj(route_ptr->http_method, route_ptr->http_method_len);
        Tcl_Obj *path_ptr = Tcl_NewStringObj(route_ptr->path, route_ptr->path_len);
        Tcl_Obj *proc_name_ptr = Tcl_NewStringObj(route_ptr->proc_name, route_ptr->proc_name_len);
        Tcl_Obj *type_ptr = Tcl_NewStringObj(route_ptr->type == ROUTE_TYPE_EXACT ? "exact" : "regexp", -1);
        Tcl_Obj *option_prefix_ptr = Tcl_NewBooleanObj(route_ptr->option_prefix);
        Tcl_Obj *option_nocase_ptr = Tcl_NewBooleanObj(route_ptr->option_nocase);
        Tcl_Obj *option_strict_ptr = Tcl_NewBooleanObj(route_ptr->option_strict);
        Tcl_Obj *fast_star_ptr = Tcl_NewBooleanObj(route_ptr->fast_star);
        Tcl_Obj *fast_slash_ptr = Tcl_NewBooleanObj(route_ptr->fast_slash);
        Tcl_Obj *pattern_ptr = Tcl_NewStringObj(route_ptr->pattern ? route_ptr->pattern : "", -1);

        Tcl_Obj *values[] = {
                http_method_ptr,
                path_ptr,
                proc_name_ptr,
                type_ptr,
                option_prefix_ptr,
                option_nocase_ptr,
                option_strict_ptr,
                fast_star_ptr,
                fast_slash_ptr,
                pattern_ptr,
                NULL
        };
        Tcl_Obj *keys[] = {
                Tcl_NewStringObj("http_method", -1),
                Tcl_NewStringObj("path", -1),
                Tcl_NewStringObj("proc_name", -1),
                Tcl_NewStringObj("type", -1),
                Tcl_NewStringObj("option_prefix", -1),
                Tcl_NewStringObj("option_nocase", -1),
                Tcl_NewStringObj("option_strict", -1),
                Tcl_NewStringObj("fast_star", -1),
                Tcl_NewStringObj("fast_slash", -1),
                Tcl_NewStringObj("pattern", -1),
                NULL
        };
        for (int i = 0; keys[i] != NULL; i++) {
            Tcl_DictObjPut(interp, route_dict_ptr, keys[i], values[i]);
        }
        Tcl_ListObjAppendElement(interp, result_ptr, route_dict_ptr);

        route_ptr = route_ptr->nextPtr;
    }
    Tcl_SetObjResult(interp, result_ptr);
    return TCL_OK;
}


int tws_AddMiddlewareCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AddMiddlewareCmd\n"));

    const char *enter_proc;
    const char *leave_proc;
    Tcl_ArgvInfo ArgTable[] = {
            {TCL_ARGV_STRING, "-enter_proc", NULL, &enter_proc, "enter proc"},
            {TCL_ARGV_STRING, "-leave_proc", NULL, &leave_proc, "leave proc"},
            {TCL_ARGV_END, NULL,             NULL, NULL, NULL}
    };
    Tcl_Obj **remObjv;
    Tcl_ParseArgsObjv(interp, ArgTable, &objc, objv, &remObjv);

    if ((objc < 2) || (objc > 2)) {
        Tcl_WrongNumArgs(interp, 1, remObjv, "router_handle");
        return TCL_ERROR;
    }

    if (!enter_proc && !leave_proc) {
        SetResult("add_middleware: at least one of -enter_proc or -leave_proc must be specified");
        return TCL_ERROR;
    }

    tws_router_t *router_ptr = tws_GetInternalFromRouterName(Tcl_GetString(remObjv[1]));
    if (!router_ptr) {
        SetResult("add_middleware: router handle not found");
        return TCL_ERROR;
    }

    tws_middleware_t *middleware_ptr = (tws_middleware_t *) Tcl_Alloc(sizeof(tws_middleware_t));
    if (!middleware_ptr) {
        SetResult("add_middleware: memory alloc failed");
        return TCL_ERROR;
    }

    if (enter_proc) {
        middleware_ptr->enter_proc_ptr = Tcl_NewStringObj(enter_proc, -1);
        Tcl_IncrRefCount(middleware_ptr->enter_proc_ptr);
    } else {
        middleware_ptr->enter_proc_ptr = NULL;
    }

    if (leave_proc) {
        middleware_ptr->leave_proc_ptr = Tcl_NewStringObj(leave_proc, -1);
        Tcl_IncrRefCount(middleware_ptr->leave_proc_ptr);
    } else {
        middleware_ptr->leave_proc_ptr = NULL;
    }

    middleware_ptr->nextPtr = NULL;
    if (router_ptr->firstMiddlewarePtr == NULL) {
        middleware_ptr->prevPtr = NULL;
        router_ptr->firstMiddlewarePtr = middleware_ptr;
        router_ptr->lastMiddlewarePtr = middleware_ptr;
    } else {
        middleware_ptr->prevPtr = router_ptr->lastMiddlewarePtr;
        router_ptr->lastMiddlewarePtr->nextPtr = middleware_ptr;
        router_ptr->lastMiddlewarePtr = middleware_ptr;
    }

    return TCL_OK;
}