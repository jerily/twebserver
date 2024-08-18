/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#include "common.h"
#include "router.h"
#include "path_regexp/path_regexp.h"
#include "return.h"
#include <string.h>
#include <assert.h>

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

        DBG2(printf("matched pattern: %s", route_ptr->pattern));

        Tcl_Size keys_objc;
        Tcl_Obj **keys_objv;
        Tcl_ListObjGetElements(interp, route_ptr->keys, &keys_objc, &keys_objv);
        Tcl_Obj *pathParametersDictPtr = Tcl_NewDictObj();
        Tcl_IncrRefCount(pathParametersDictPtr);
        const char *start;
        const char *end;
        for (int i = 0; i < keys_objc; i++) {
            Tcl_RegExpRange(regexp, i + 1, &start, &end);
            Tcl_Obj *key_ptr = keys_objv[i];
            Tcl_Obj *value_ptr = Tcl_NewStringObj(start, end - start);
            Tcl_IncrRefCount(value_ptr);

            DBG2(printf("key: %s, value: %s", Tcl_GetString(key_ptr), Tcl_GetString(value_ptr)));

            if (TCL_OK != Tcl_DictObjPut(interp, pathParametersDictPtr, key_ptr, value_ptr)) {
                Tcl_DecrRefCount(value_ptr);
                Tcl_DecrRefCount(pathParametersDictPtr);
                SetResult("MatchRoute: dict put failed");
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(value_ptr);
        }

        Tcl_Obj *pathParametersKeyPtr = Tcl_NewStringObj("pathParameters", -1);
        Tcl_IncrRefCount(pathParametersKeyPtr);
        if (TCL_OK != Tcl_DictObjPut(interp, requestDictPtr, pathParametersKeyPtr, pathParametersDictPtr)) {
            Tcl_DecrRefCount(pathParametersKeyPtr);
            Tcl_DecrRefCount(pathParametersDictPtr);
            SetResult("MatchRoute: dict put failed");
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(pathParametersKeyPtr);
        Tcl_DecrRefCount(pathParametersDictPtr);
    } else {
        *matched = 0;
    }
    return TCL_OK;
}

static int tws_MatchExactRoute(tws_route_t *route_ptr, Tcl_Obj *path_ptr, int *matched) {
    Tcl_Size path_len;
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

static int tws_MatchRoute(Tcl_Interp *interp, tws_route_t *route_ptr, Tcl_Obj *dup_req_dict_ptr, int *matched) {
    Tcl_Obj *http_method_key_ptr = Tcl_NewStringObj("httpMethod", -1);
    Tcl_IncrRefCount(http_method_key_ptr);
    Tcl_Obj *http_method_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, dup_req_dict_ptr, http_method_key_ptr, &http_method_ptr)) {
        Tcl_DecrRefCount(http_method_key_ptr);
        SetResult("MatchRoute: dict get failed");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(http_method_key_ptr);

    if (!http_method_ptr) {
        *matched = 0;
        return TCL_OK;
    }

    Tcl_Size http_method_len;
    const char *http_method = Tcl_GetStringFromObj(http_method_ptr, &http_method_len);

    Tcl_Obj *path_key_ptr = Tcl_NewStringObj("path", -1);
    Tcl_IncrRefCount(path_key_ptr);
    Tcl_Obj *path_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, dup_req_dict_ptr, path_key_ptr, &path_ptr)) {
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
            if (TCL_OK != tws_MatchExactRoute(route_ptr, path_ptr, matched)) {
                SetResult("MatchRoute: match_exact_route failed");
                return TCL_ERROR;
            }
        } else {
            if (TCL_OK != tws_MatchRegExpRoute(interp, route_ptr, path_ptr, dup_req_dict_ptr, matched)) {
                SetResult("MatchRoute: match_regexp_route failed");
                return TCL_ERROR;
            }
        }

    } else {
        *matched = 0;
    }

    return TCL_OK;
}

// traverse middleware leave procs in reverse order
static int tws_ProcessMiddlewareLeaveProcs(
        Tcl_Interp *interp,
        tws_middleware_t *middleware_ptr,
        Tcl_Obj *ctx_dict_ptr,
        Tcl_Obj *req_dict_ptr,
        Tcl_Obj **res_dict_ptr_ptr
) {
    Tcl_Obj *res_dict_ptr = *res_dict_ptr_ptr;
    while (middleware_ptr != NULL) {
        if (middleware_ptr->leave_proc_ptr) {

            DBG2(printf("res_dict_ptr, IsShared: %d", Tcl_IsShared(res_dict_ptr)));

            Tcl_Obj *const proc_objv[] = {middleware_ptr->leave_proc_ptr, ctx_dict_ptr, req_dict_ptr, res_dict_ptr};
            if (TCL_OK != Tcl_EvalObjv(interp, 4, proc_objv, TCL_EVAL_GLOBAL)) {
                *res_dict_ptr_ptr = res_dict_ptr;
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(res_dict_ptr);
            res_dict_ptr = Tcl_GetObjResult(interp);
            Tcl_IncrRefCount(res_dict_ptr);
            Tcl_ResetResult(interp);
        }
        middleware_ptr = middleware_ptr->prevPtr;
    }
    *res_dict_ptr_ptr = res_dict_ptr;
    return TCL_OK;
}

static int tws_HandleGuardProcError(
        Tcl_Interp *interp,
        tws_conn_t *conn,
        tws_router_t *router_ptr,
        Tcl_Obj *ctx_dict_ptr,
        Tcl_Obj *req_dict_ptr
) {
    Tcl_Obj *return_options_dict_ptr = Tcl_GetReturnOptions(interp, TCL_ERROR);
    Tcl_IncrRefCount(return_options_dict_ptr);
    Tcl_Obj *status_code_ptr;
    Tcl_Obj *status_code_key_ptr = Tcl_NewStringObj("statusCode", -1);
    Tcl_IncrRefCount(status_code_key_ptr);
    if (TCL_OK != Tcl_DictObjGet(interp, return_options_dict_ptr, status_code_key_ptr,
                                 &status_code_ptr)) {
        Tcl_DecrRefCount(status_code_key_ptr);
        Tcl_DecrRefCount(return_options_dict_ptr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(status_code_key_ptr);

    if (status_code_ptr) {
        DBG2(printf("returning error response\n"));
        Tcl_Obj *res_dict_ptr = Tcl_DuplicateObj(return_options_dict_ptr);
        Tcl_IncrRefCount(res_dict_ptr);
        if (TCL_OK !=
            tws_ProcessMiddlewareLeaveProcs(interp, router_ptr->lastMiddlewarePtr, ctx_dict_ptr, req_dict_ptr, &res_dict_ptr)) {
            DBG2(printf("leave procs failed\n"));
            Tcl_DecrRefCount(return_options_dict_ptr);
            Tcl_DecrRefCount(res_dict_ptr);
            return TCL_ERROR;
        }

        if (TCL_OK != tws_ReturnConn(interp, conn, res_dict_ptr)) {
            DBG2(printf("return conn failed\n"));
            Tcl_DecrRefCount(return_options_dict_ptr);
            Tcl_DecrRefCount(res_dict_ptr);
            return TCL_ERROR;
        }
        DBG2(printf("return conn done\n"));


        Tcl_DecrRefCount(return_options_dict_ptr);
        Tcl_DecrRefCount(res_dict_ptr);
        Tcl_ResetResult(interp);
        return TCL_OK;
    }
    Tcl_DecrRefCount(return_options_dict_ptr);
    return TCL_ERROR;
}

static int tws_ProcessRouteGuardProcs(
        Tcl_Interp *interp,
        tws_conn_t *conn,
        tws_router_t *router_ptr,
        tws_route_t *route_ptr,
        Tcl_Obj *ctx_dict_ptr,
        Tcl_Obj **req_dict_ptr_ptr,
        int *done
) {
    Tcl_Obj *req_dict_ptr = *req_dict_ptr_ptr;
    if (route_ptr->guard_list_ptr != NULL) {
        Tcl_Size guard_objc;
        Tcl_Obj **guard_objv;
        if (TCL_OK != Tcl_ListObjGetElements(interp, route_ptr->guard_list_ptr, &guard_objc, &guard_objv)) {
            return TCL_ERROR;
        }

        for (Tcl_Size i = 0; i < guard_objc; i++) {
            Tcl_Obj *const eval_objv[] = {guard_objv[i], ctx_dict_ptr, req_dict_ptr};
            if (TCL_OK != Tcl_EvalObjv(interp, 3, eval_objv, TCL_EVAL_GLOBAL)) {

                if (TCL_OK == tws_HandleGuardProcError(interp, conn, router_ptr, ctx_dict_ptr, req_dict_ptr)) {
                    *req_dict_ptr_ptr = req_dict_ptr;
                    *done = 1;
                    return TCL_OK;
                }

                *req_dict_ptr_ptr = req_dict_ptr;
                return TCL_ERROR;
            }

            Tcl_DecrRefCount(req_dict_ptr);
            req_dict_ptr = Tcl_GetObjResult(interp);
            Tcl_IncrRefCount(req_dict_ptr);
            Tcl_ResetResult(interp);
        }
    }
    *req_dict_ptr_ptr = req_dict_ptr;
    return TCL_OK;
}

static int tws_EvalRoute(
        Tcl_Interp *interp,
        tws_conn_t *conn,
        tws_router_t *router_ptr,
        tws_route_t *route_ptr,
        Tcl_Obj *ctx_dict_ptr,
        Tcl_Obj **req_dict_ptr_ptr,
        int *done
) {
    DBG2(printf("eval route: %s", route_ptr->proc_name));

    Tcl_Obj *req_dict_ptr = *req_dict_ptr_ptr;

    int done_during_guard_procs = 0;
    if (TCL_OK != tws_ProcessRouteGuardProcs(interp, conn, router_ptr, route_ptr, ctx_dict_ptr, &req_dict_ptr, &done_during_guard_procs)) {
        *req_dict_ptr_ptr = req_dict_ptr;
        return TCL_ERROR;
    }

    if (done_during_guard_procs) {
        *done = 1;
        *req_dict_ptr_ptr = req_dict_ptr;
        return TCL_OK;
    }

    Tcl_Obj *proc_name_ptr = Tcl_NewStringObj(route_ptr->proc_name, -1);
    Tcl_IncrRefCount(proc_name_ptr);
    Tcl_Obj *const proc_objv[] = {proc_name_ptr, ctx_dict_ptr, req_dict_ptr};
    if (TCL_OK != Tcl_EvalObjv(interp, 3, proc_objv, TCL_EVAL_GLOBAL)) {
        Tcl_DecrRefCount(proc_name_ptr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(proc_name_ptr);
    return TCL_OK;
}

static int tws_HandleMiddlewareEnterError(
        Tcl_Interp *interp,
        tws_conn_t *conn,
        tws_middleware_t *middleware_ptr,
        Tcl_Obj *ctx_dict_ptr,
        Tcl_Obj *req_dict_ptr
) {
    Tcl_Obj *return_options_dict_ptr = Tcl_GetReturnOptions(interp, TCL_ERROR);
    Tcl_IncrRefCount(return_options_dict_ptr);
    Tcl_Obj *status_code_ptr;
    Tcl_Obj *status_code_key_ptr = Tcl_NewStringObj("statusCode", -1);
    Tcl_IncrRefCount(status_code_key_ptr);
    if (TCL_OK != Tcl_DictObjGet(interp, return_options_dict_ptr, status_code_key_ptr,
                                 &status_code_ptr)) {
        Tcl_DecrRefCount(status_code_key_ptr);
        Tcl_DecrRefCount(return_options_dict_ptr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(status_code_key_ptr);

    if (status_code_ptr) {
        DBG2(printf("returning error response\n"));
        Tcl_Obj *res_dict_ptr = Tcl_DuplicateObj(return_options_dict_ptr);
        Tcl_IncrRefCount(res_dict_ptr);
        if (TCL_OK !=
            tws_ProcessMiddlewareLeaveProcs(interp, middleware_ptr, ctx_dict_ptr, req_dict_ptr, &res_dict_ptr)) {
            DBG2(printf("leave procs failed\n"));
            Tcl_DecrRefCount(return_options_dict_ptr);
            Tcl_DecrRefCount(res_dict_ptr);
            return TCL_ERROR;
        }

        if (TCL_OK != tws_ReturnConn(interp, conn, res_dict_ptr)) {
            DBG2(printf("return conn failed\n"));
            Tcl_DecrRefCount(return_options_dict_ptr);
            Tcl_DecrRefCount(res_dict_ptr);
            return TCL_ERROR;
        }
        DBG2(printf("return conn done\n"));
        Tcl_DecrRefCount(return_options_dict_ptr);
        Tcl_DecrRefCount(res_dict_ptr);
        Tcl_ResetResult(interp);
        return TCL_OK;
    }
    Tcl_DecrRefCount(return_options_dict_ptr);
    return TCL_ERROR;
}

static int tws_ProcessMiddlewareEnterProcs(
        Tcl_Interp *interp,
        tws_conn_t *conn,
        tws_middleware_t *middleware_ptr,
        Tcl_Obj *ctx_dict_ptr,
        Tcl_Obj **req_dict_ptr_ptr,
        int *done
) {

    Tcl_Obj *req_dict_ptr = *req_dict_ptr_ptr;

    while (middleware_ptr != NULL) {
        if (middleware_ptr->enter_proc_ptr) {

            DBG2(printf("req_dict_ptr, IsShared: %d", Tcl_IsShared(req_dict_ptr)));

            Tcl_Obj *const proc_objv[] = {middleware_ptr->enter_proc_ptr, ctx_dict_ptr, req_dict_ptr};
            DBG(tws_PrintRefCountObjv(3, proc_objv));
            if (TCL_OK != Tcl_EvalObjv(interp, 3, proc_objv, TCL_EVAL_GLOBAL)) {

                if (TCL_OK ==
                    tws_HandleMiddlewareEnterError(interp, conn, middleware_ptr, ctx_dict_ptr, req_dict_ptr)) {
                    DBG2(printf("middleware enter error handled\n"));
                    *req_dict_ptr_ptr = req_dict_ptr;
                    *done = 1;
                    return TCL_OK;
                }

                *req_dict_ptr_ptr = req_dict_ptr;
                return TCL_ERROR;
            }

            Tcl_DecrRefCount(req_dict_ptr);
            req_dict_ptr = Tcl_GetObjResult(interp);
            Tcl_IncrRefCount(req_dict_ptr);

            Tcl_ResetResult(interp);

        }
        middleware_ptr = middleware_ptr->nextPtr;
    }
    *req_dict_ptr_ptr = req_dict_ptr;
    return TCL_OK;
}

static int tws_ProcessRoute(Tcl_Interp *interp, tws_conn_t *conn, tws_router_t *router_ptr, tws_route_t *route_ptr,
                            Tcl_Obj *ctx_dict_ptr, Tcl_Obj *req_dict_ptr) {
    assert(valid_conn_handle(conn));

    Tcl_ResetResult(interp);

    // traverse middleware enter procs
    int done_during_enter_middleware = 0;
    if (TCL_OK !=
        tws_ProcessMiddlewareEnterProcs(interp, conn, router_ptr->firstMiddlewarePtr, ctx_dict_ptr, &req_dict_ptr, &done_during_enter_middleware)) {
        Tcl_DecrRefCount(req_dict_ptr);
        return TCL_ERROR;
    }

    if (done_during_enter_middleware) {
        Tcl_DecrRefCount(req_dict_ptr);
        return TCL_OK;
    }

    DBG2(printf("req: %s", Tcl_GetString(req_dict_ptr)));

    // eval route proc
    int done_during_eval_route = 0;
    if (TCL_OK != tws_EvalRoute(interp, conn, router_ptr, route_ptr, ctx_dict_ptr, &req_dict_ptr, &done_during_eval_route)) {
        DBG2(printf("router_process_conn: eval route failed path: %s", route_ptr->path));
        Tcl_DecrRefCount(req_dict_ptr);
        return TCL_ERROR;
    }

    if (done_during_eval_route) {
        Tcl_DecrRefCount(req_dict_ptr);
        return TCL_OK;
    }

    Tcl_Obj *res_dict_ptr = Tcl_GetObjResult(interp);
    Tcl_IncrRefCount(res_dict_ptr);
    Tcl_ResetResult(interp);

    // traverse middleware leave procs in reverse order
    if (TCL_OK != tws_ProcessMiddlewareLeaveProcs(interp, router_ptr->lastMiddlewarePtr, ctx_dict_ptr, req_dict_ptr,
                                                  &res_dict_ptr)) {
        Tcl_DecrRefCount(req_dict_ptr);
        Tcl_DecrRefCount(res_dict_ptr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(req_dict_ptr);

    // return response
    if (TCL_OK != tws_ReturnConn(interp, conn, res_dict_ptr)) {
        Tcl_DecrRefCount(res_dict_ptr);
        return TCL_ERROR;
    }
    Tcl_ResetResult(interp);
    Tcl_DecrRefCount(res_dict_ptr);
    return TCL_OK;
}

int tws_CreateContextDict(Tcl_Interp *interp, tws_conn_t *conn, Tcl_Obj **result_ptr) {

    Tcl_Obj *ctx_dict_ptr = Tcl_NewDictObj();
    Tcl_IncrRefCount(ctx_dict_ptr);

    if (TCL_OK != Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("server", -1),
                                 Tcl_NewStringObj(conn->accept_ctx->server->handle, -1))) {
        Tcl_DecrRefCount(ctx_dict_ptr);
        SetResult("router_process_conn: dict put failed");
        return TCL_ERROR;
    }
    if (TCL_OK !=
        Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("conn", -1), Tcl_NewStringObj(conn->handle, -1))) {
        Tcl_DecrRefCount(ctx_dict_ptr);
        SetResult("router_process_conn: dict put failed");
        return TCL_ERROR;
    }
    if (TCL_OK !=
        Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("addr", -1), Tcl_NewStringObj(conn->client_ip, -1))) {
        Tcl_DecrRefCount(ctx_dict_ptr);
        SetResult("router_process_conn: dict put failed");
        return TCL_ERROR;
    }
    if (TCL_OK !=
        Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("port", -1), Tcl_NewIntObj(conn->accept_ctx->port))) {
        Tcl_DecrRefCount(ctx_dict_ptr);
        SetResult("router_process_conn: dict put failed");
        return TCL_ERROR;
    }
    if (TCL_OK != Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("isSecureProto", -1),
                                 Tcl_NewBooleanObj(!conn->accept_ctx->option_http))) {
        Tcl_DecrRefCount(ctx_dict_ptr);
        SetResult("router_process_conn: dict put failed");
        return TCL_ERROR;
    }

    *result_ptr = ctx_dict_ptr;
    return TCL_OK;
}

static int tws_DoRouting(Tcl_Interp *interp, tws_router_t *router_ptr, tws_conn_t *conn, Tcl_Obj *dup_req_dict_ptr) {
    DBG2(printf("DoRouting\n"));

    Tcl_Obj *ctx_dict_ptr;
    if (TCL_OK != tws_CreateContextDict(interp, conn, &ctx_dict_ptr)) {
        Tcl_DecrRefCount(dup_req_dict_ptr);
        return TCL_ERROR;
    }

    tws_route_t *route_ptr = router_ptr->firstRoutePtr;
    while (route_ptr != NULL) {
        int matched = 0;
        if (TCL_OK != tws_MatchRoute(interp, route_ptr, dup_req_dict_ptr, &matched)) {
            Tcl_DecrRefCount(ctx_dict_ptr);
            Tcl_DecrRefCount(dup_req_dict_ptr);
            SetResult("router_process_conn: match_route failed");
            return TCL_ERROR;
        }

        if (matched) {
            // tws_ProcessRoute decrements ref count for dup_req_dict_ptr in any case
            if (TCL_OK != tws_ProcessRoute(interp, conn, router_ptr, route_ptr, ctx_dict_ptr, dup_req_dict_ptr)) {
                Tcl_DecrRefCount(ctx_dict_ptr);
                return TCL_ERROR;
            }
            break;
        }
        route_ptr = route_ptr->nextPtr;
    }

    Tcl_DecrRefCount(ctx_dict_ptr);

    if (route_ptr == NULL) {
        Tcl_DecrRefCount(dup_req_dict_ptr);
        if (TCL_OK != tws_ReturnError(interp, conn, 404, "Not Found")) {
            return TCL_ERROR;
        }
    }

    return TCL_OK;
}

int tws_HandleRouteEventInThread(tws_router_t *router, tws_conn_t *conn, Tcl_Obj *dup_req_dict_ptr) {

    DBG2(printf("HandleRouteEventInThread: %s", conn->handle));
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(tws_GetThreadDataKey(),
                                                                         sizeof(tws_thread_data_t));

    if (TCL_OK != tws_DoRouting(dataPtr->interp, router, conn, dup_req_dict_ptr)) {
        DBG2(printf("DoRouting failed: %s", Tcl_GetString(Tcl_GetObjResult(dataPtr->interp))));

        Tcl_Obj *return_options_dict_ptr = Tcl_GetReturnOptions(dataPtr->interp, TCL_ERROR);
        Tcl_IncrRefCount(return_options_dict_ptr);
        Tcl_Obj *errorinfo_ptr;
        Tcl_Obj *errorinfo_key_ptr = Tcl_NewStringObj("-errorinfo", -1);
        Tcl_IncrRefCount(errorinfo_key_ptr);
        if (TCL_OK != Tcl_DictObjGet(dataPtr->interp, return_options_dict_ptr, errorinfo_key_ptr,
                                     &errorinfo_ptr)) {
            Tcl_DecrRefCount(errorinfo_key_ptr);
            Tcl_DecrRefCount(return_options_dict_ptr);
            tws_CloseConn(conn, 1);
            return 1;
        }
        Tcl_DecrRefCount(errorinfo_key_ptr);

        fprintf(stderr, "DoRouting: errorinfo: %s", Tcl_GetString(errorinfo_ptr));
        Tcl_DecrRefCount(return_options_dict_ptr);

        if (TCL_OK != tws_ReturnError(dataPtr->interp, conn, 500, "Internal Server Error")) {
            tws_CloseConn(conn, 1);
            return 1;
        }

        // close not needed here as ReturnError will close the connection after it writes the response
        return 1;
    }

    DBG2(printf("DoRouting done\n"));
    return 1;
}

static int tws_RouterProcessConnCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG2(printf("RouterProcessConnCmd\n"));
    CheckArgs(3, 3, 1, "ctx_dict req_dict");

    const char *handle = (const char *) clientData;
    tws_router_t *router_ptr = tws_GetInternalFromRouterName(handle);
    if (!router_ptr) {
        SetResult("router_process_conn: router handle not found");
        return TCL_ERROR;
    }

    Tcl_Obj *conn_key_ptr = Tcl_NewStringObj("conn", -1);
    Tcl_IncrRefCount(conn_key_ptr);
    Tcl_Obj *conn_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, objv[1], conn_key_ptr, &conn_ptr)) {
        Tcl_DecrRefCount(conn_key_ptr);
        SetResult("router_process_conn: dict get failed");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(conn_key_ptr);

    if (!conn_ptr) {
        SetResult("router_process_conn: conn not found in ctx dict");
        return TCL_ERROR;
    }

    const char *conn_handle = Tcl_GetString(conn_ptr);
    tws_conn_t *conn = tws_GetInternalFromConnName(conn_handle);
    if (!conn) {
        SetResult("router_process_conn: conn handle not found");
        return TCL_ERROR;
    }
    Tcl_Obj *dup_req_dict_ptr = Tcl_DuplicateObj(objv[2]);
    Tcl_IncrRefCount(dup_req_dict_ptr);
    tws_HandleRouteEventInThread(router_ptr, conn, dup_req_dict_ptr);
    return TCL_OK;
}

static int tws_DestroyRouter(Tcl_Interp *interp, const char *handle) {
    DBG2(printf("DestroyRouter: %s", handle));
    tws_router_t *router_ptr = tws_GetInternalFromRouterName(handle);
    if (!router_ptr) {
        SetResult("DestroyRouter: router handle not found");
        return TCL_ERROR;
    }

    if (TCL_OK != tws_UnregisterRouterName(handle)) {
        SetResult("DestroyRouter: unregister_router_name failed");
        return TCL_ERROR;
    }

    Tcl_DeleteCommand(interp, router_ptr->handle);

    tws_route_t *route = router_ptr->firstRoutePtr;
    while (route) {
        tws_route_t *next = route->nextPtr;
        if (route->guard_list_ptr != NULL) {
            Tcl_DecrRefCount(route->guard_list_ptr);
        }
        Tcl_DecrRefCount(route->keys);
        ckfree(route->pattern);
        ckfree((char *) route);
        route = next;
    }

    tws_middleware_t *middleware = router_ptr->firstMiddlewarePtr;
    while (middleware) {
        tws_middleware_t *next = middleware->nextPtr;
        if (middleware->enter_proc_ptr) {
            tws_DecrRefCountUntilZero(middleware->enter_proc_ptr);
        }
        if (middleware->leave_proc_ptr) {
            tws_DecrRefCountUntilZero(middleware->leave_proc_ptr);
        }
        ckfree((char *) middleware);
        middleware = next;
    }

    ckfree((char *) router_ptr);

    fprintf(stderr, "router destroyed\n");

    return TCL_OK;
}

static char VAR_READ_ONLY_MSG[] = "var is read-only";

char *tws_VarTraceProc(ClientData clientData, Tcl_Interp *interp, const char *name1, const char *name2, int flags) {
    UNUSED(interp);

    tws_trace_t *trace = (tws_trace_t *) clientData;
    if (trace->item == NULL) {
        DBG2(printf("VarTraceProc: router has been deleted\n"));
        if (!Tcl_InterpDeleted(trace->interp)) {
            Tcl_UntraceVar(trace->interp, trace->varname, TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
                           (Tcl_VarTraceProc *) tws_VarTraceProc,
                           (ClientData) clientData);
        }
        ckfree((char *) trace->varname);
        ckfree((char *) trace);
        return NULL;
    }
    if (flags & TCL_TRACE_WRITES) {
        DBG2(printf("VarTraceProc: TCL_TRACE_WRITES\n"));
        Tcl_SetVar2(trace->interp, name1, name2, ((tws_router_t *) trace->item)->handle, TCL_LEAVE_ERR_MSG);
        return VAR_READ_ONLY_MSG;
    }
    if (flags & TCL_TRACE_UNSETS) {
        DBG2(printf("VarTraceProc: TCL_TRACE_UNSETS\n"));
        tws_DestroyRouter(trace->interp, ((tws_router_t *) trace->item)->handle);
        ckfree((char *) trace->varname);
        ckfree((char *) trace);
    }
    return NULL;
}

int tws_CreateRouterCmd(ClientData clientData, Tcl_Interp *interp, int incoming_objc, Tcl_Obj *const objv[]) {
    UNUSED(clientData);

    DBG2(printf("CreateCmd\n"));

    const char *option_command_name = NULL;
    Tcl_ArgvInfo ArgTable[] = {
            {TCL_ARGV_STRING, "-command_name", NULL, &option_command_name, "router command name", NULL},
            {TCL_ARGV_END, NULL,               NULL, NULL, NULL,                                  NULL}
    };

    Tcl_Obj **remObjv;
    Tcl_Size objc = incoming_objc;
    Tcl_ParseArgsObjv(interp, ArgTable, &objc, objv, &remObjv);

    if (objc < 1 || objc > 2) {
        ckfree(remObjv);
        Tcl_WrongNumArgs(interp, 1, remObjv, "?varname?");
        return TCL_ERROR;
    }

    tws_router_t *router_ptr = (tws_router_t *) ckalloc(sizeof(tws_router_t));
    if (!router_ptr) {
        ckfree(remObjv);
        SetResult("create_router: memory alloc failed");
        return TCL_ERROR;
    }
    router_ptr->firstRoutePtr = NULL;
    router_ptr->lastRoutePtr = NULL;
    router_ptr->firstMiddlewarePtr = NULL;
    router_ptr->lastMiddlewarePtr = NULL;

    CMD_ROUTER_NAME(router_ptr->handle, router_ptr);
    tws_RegisterRouterName(router_ptr->handle, router_ptr);
    DBG2(printf("creating obj cmd\n"));
    const char *command_name = option_command_name ? option_command_name : router_ptr->handle;
    Tcl_CreateObjCommand(interp, command_name, tws_RouterProcessConnCmd, (ClientData) router_ptr->handle, NULL);
    DBG2(printf("done creating obj cmd\n"));

    if (objc == 2) {
        tws_trace_t *trace = (tws_trace_t *) ckalloc(sizeof(tws_trace_t));
        trace->interp = interp;
        trace->varname = tws_strndup(Tcl_GetString(remObjv[1]), 80);
        trace->item = router_ptr;
        const char *objVar = Tcl_GetString(remObjv[1]);
        Tcl_UnsetVar(interp, objVar, 0);
        Tcl_SetVar  (interp, objVar, router_ptr->handle, 0);
        Tcl_TraceVar(interp, objVar, TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
                     (Tcl_VarTraceProc *) tws_VarTraceProc,
                     (ClientData) trace);
    }

    SetResult(router_ptr->handle);
    ckfree(remObjv);
    return TCL_OK;

}

int tws_AddRouteCmd(ClientData clientData, Tcl_Interp *interp, int incoming_objc, Tcl_Obj *const objv[]) {
    UNUSED(clientData);

    DBG2(printf("AddRouteCmd\n"));

    int option_prefix = 0;
    int option_nocase = 0;
    int option_strict = 0;
    const char *option_guard_proc_list = NULL;
    Tcl_ArgvInfo ArgTable[] = {
            {TCL_ARGV_STRING,   "-guard_proc_list", NULL,       &option_guard_proc_list, "guard proc list",  NULL},
            {TCL_ARGV_CONSTANT, "-prefix",          INT2PTR(1), &option_prefix,          "prefix matching",  NULL},
            {TCL_ARGV_CONSTANT, "-nocase",          INT2PTR(1), &option_nocase,          "case insensitive", NULL},
            {TCL_ARGV_CONSTANT, "-strict",          INT2PTR(1), &option_strict,          "strict matching",  NULL},
            {TCL_ARGV_END, NULL,                    NULL, NULL, NULL,                                        NULL}
    };
    Tcl_Obj **remObjv;
    Tcl_Size objc = incoming_objc;
    Tcl_ParseArgsObjv(interp, ArgTable, &objc, objv, &remObjv);

    if ((objc < 5) || (objc > 5)) {
        ckfree(remObjv);
        Tcl_WrongNumArgs(interp, 1, remObjv, "router_handle http_method path proc_name");
        return TCL_ERROR;
    }

    if (option_prefix && option_strict) {
        ckfree(remObjv);
        SetResult("add_route: option -prefix and -strict are mutually exclusive");
        return TCL_ERROR;
    }

    tws_router_t *router_ptr = tws_GetInternalFromRouterName(Tcl_GetString(remObjv[1]));
    if (!router_ptr) {
        ckfree(remObjv);
        SetResult("add_route: router handle not found");
        return TCL_ERROR;
    }
    Tcl_Size http_method_len;
    const char *http_method = Tcl_GetStringFromObj(remObjv[2], &http_method_len);
    Tcl_Size path_len;
    const char *path = Tcl_GetStringFromObj(remObjv[3], &path_len);
    Tcl_Size proc_name_len;
    const char *proc_name = Tcl_GetStringFromObj(remObjv[4], &proc_name_len);

    tws_route_t *route_ptr = (tws_route_t *) ckalloc(sizeof(tws_route_t));
    if (!route_ptr) {
        ckfree(remObjv);
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
    route_ptr->guard_list_ptr = NULL;

    if (option_guard_proc_list != NULL) {
        Tcl_Obj *guard_list_ptr = Tcl_NewStringObj(option_guard_proc_list, -1);
        Tcl_IncrRefCount(guard_list_ptr);
        route_ptr->guard_list_ptr = guard_list_ptr;
    }

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
                ckfree(remObjv);
//                SetResult("add_route: path_to_regexp failed");
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

    ckfree(remObjv);
    return TCL_OK;
}

int tws_InfoRoutesCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    UNUSED(clientData);

    DBG2(printf("AddRouteCmd\n"));
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


int tws_AddMiddlewareCmd(ClientData clientData, Tcl_Interp *interp, int incoming_objc, Tcl_Obj *const objv[]) {
    UNUSED(clientData);

    DBG2(printf("AddMiddlewareCmd\n"));

    const char *enter_proc = NULL;
    const char *leave_proc = NULL;
    Tcl_ArgvInfo ArgTable[] = {
            {TCL_ARGV_STRING, "-enter_proc", NULL, &enter_proc, "enter proc", NULL},
            {TCL_ARGV_STRING, "-leave_proc", NULL, &leave_proc, "leave proc", NULL},
            {TCL_ARGV_END, NULL,             NULL, NULL, NULL,                NULL}
    };
    Tcl_Obj **remObjv;
    Tcl_Size objc = incoming_objc;
    Tcl_ParseArgsObjv(interp, ArgTable, &objc, objv, &remObjv);

    if ((objc < 2) || (objc > 2)) {
        ckfree(remObjv);
        Tcl_WrongNumArgs(interp, 1, remObjv, "router_handle");
        return TCL_ERROR;
    }

    if (!enter_proc && !leave_proc) {
        ckfree(remObjv);
        SetResult("add_middleware: at least one of -enter_proc or -leave_proc must be specified");
        return TCL_ERROR;
    }

    tws_router_t *router_ptr = tws_GetInternalFromRouterName(Tcl_GetString(remObjv[1]));
    if (!router_ptr) {
        ckfree(remObjv);
        SetResult("add_middleware: router handle not found");
        return TCL_ERROR;
    }

    tws_middleware_t *middleware_ptr = (tws_middleware_t *) ckalloc(sizeof(tws_middleware_t));
    if (!middleware_ptr) {
        ckfree(remObjv);
        SetResult("add_middleware: memory alloc failed");
        return TCL_ERROR;
    }

    if (enter_proc && strlen(enter_proc) > 0) {
        DBG2(printf("enter_proc: %s (%ld)", enter_proc, strlen(enter_proc)));
        middleware_ptr->enter_proc_ptr = Tcl_NewStringObj(enter_proc, -1);
        Tcl_IncrRefCount(middleware_ptr->enter_proc_ptr);
    } else {
        middleware_ptr->enter_proc_ptr = NULL;
    }

    if (leave_proc && strlen(leave_proc) > 0) {
        DBG2(printf("leave_proc: %s (%ld)", leave_proc, strlen(leave_proc)));
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

    ckfree(remObjv);
    return TCL_OK;
}