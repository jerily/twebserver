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

            DBG(fprintf(stderr, "key: %s, value: %s\n", Tcl_GetString(key_ptr), Tcl_GetString(value_ptr)));

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

static int tws_MatchExactRoute(Tcl_Interp *interp, tws_route_t *route_ptr, Tcl_Obj *path_ptr, int *matched) {
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

    Tcl_Size http_method_len;
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
    DBG(fprintf(stderr, "eval route: %s\n", route_ptr->proc_name));
    Tcl_Obj *proc_name_ptr = Tcl_NewStringObj(route_ptr->proc_name, -1);
    Tcl_Obj *const proc_objv[] = {proc_name_ptr, ctx_dict_ptr, req_dict_ptr};
    tws_IncrRefCountObjv(3, proc_objv);
    if (TCL_OK != Tcl_EvalObjv(interp, 3, proc_objv, TCL_EVAL_GLOBAL)) {
        tws_DecrRefCountObjv(3, proc_objv);
//        SetResult("router_process_conn: eval failed");
        return TCL_ERROR;
    }
    tws_DecrRefCountObjv(3, proc_objv);
    return TCL_OK;
}

static int tws_ProcessRoute(Tcl_Interp *interp, tws_conn_t *conn, tws_router_t *router_ptr, tws_route_t *route_ptr, Tcl_Obj *ctx_dict_ptr, Tcl_Obj *req_dict_ptr) {

    Tcl_Encoding encoding = Tcl_GetEncoding(interp, "utf-8");

    Tcl_ResetResult(interp);

    Tcl_Obj *dup_req_dict_ptr = Tcl_DuplicateObj(req_dict_ptr);
    Tcl_IncrRefCount(dup_req_dict_ptr);

    // traverse middleware enter procs
    tws_middleware_t *prev_middleware_ptr = NULL;
    tws_middleware_t *middleware_ptr = router_ptr->firstMiddlewarePtr;
    while (middleware_ptr != NULL) {
        if (middleware_ptr->enter_proc_ptr) {
            Tcl_Obj *const proc_objv[] = {middleware_ptr->enter_proc_ptr, ctx_dict_ptr, dup_req_dict_ptr};
            tws_IncrRefCountObjv(3, proc_objv);
            if (TCL_OK != Tcl_EvalObjv(interp, 3, proc_objv, TCL_EVAL_GLOBAL)) {
                tws_DecrRefCountObjv(3, proc_objv);
                return TCL_ERROR;
            }
            tws_DecrRefCountObjv(3, proc_objv);
            Tcl_DecrRefCount(dup_req_dict_ptr);
            dup_req_dict_ptr = Tcl_GetObjResult(interp);
            Tcl_IncrRefCount(dup_req_dict_ptr);
            Tcl_ResetResult(interp);
        }
        prev_middleware_ptr = middleware_ptr;
        middleware_ptr = middleware_ptr->nextPtr;
    }

    DBG(fprintf(stderr, "req: %s\n", Tcl_GetString(req_dict_ptr)));

    // eval route proc
    if (TCL_OK != tws_EvalRoute(interp, route_ptr, ctx_dict_ptr, dup_req_dict_ptr)) {
        DBG(fprintf(stderr, "router_process_conn: eval route failed path: %s\n", route_ptr->path));
        Tcl_DecrRefCount(dup_req_dict_ptr);
        return TCL_ERROR;
    }

    Tcl_Obj *res_dict_ptr = Tcl_GetObjResult(interp);
    Tcl_IncrRefCount(res_dict_ptr);
    Tcl_ResetResult(interp);

    // traverse middleware leave procs in reverse order
    middleware_ptr = prev_middleware_ptr;
    while (middleware_ptr != NULL) {
        if (middleware_ptr->leave_proc_ptr) {
            Tcl_Obj *const proc_objv[] = {middleware_ptr->leave_proc_ptr, ctx_dict_ptr, dup_req_dict_ptr,
                                          res_dict_ptr};
            tws_IncrRefCountObjv(4, proc_objv);
            if (TCL_OK != Tcl_EvalObjv(interp, 4, proc_objv, TCL_EVAL_GLOBAL)) {
                tws_DecrRefCountObjv(4, proc_objv);
                tws_DecrRefCountUntilZero(res_dict_ptr);
                Tcl_DecrRefCount(dup_req_dict_ptr);
                return TCL_ERROR;
            }
            tws_DecrRefCountObjv(4, proc_objv);
            Tcl_Obj *prev_res_dict_ptr = res_dict_ptr;
            res_dict_ptr = Tcl_GetObjResult(interp);
            Tcl_IncrRefCount(res_dict_ptr);
            Tcl_ResetResult(interp);
            Tcl_DecrRefCount(prev_res_dict_ptr);
        }
        middleware_ptr = middleware_ptr->prevPtr;
    }

    // return response
    if (TCL_OK != tws_ReturnConn(interp, conn, res_dict_ptr, encoding)) {
        tws_DecrRefCountUntilZero(res_dict_ptr);
        Tcl_DecrRefCount(dup_req_dict_ptr);
        return TCL_ERROR;
    }
    Tcl_ResetResult(interp);
    tws_DecrRefCountUntilZero(res_dict_ptr);
    Tcl_DecrRefCount(dup_req_dict_ptr);

    return TCL_OK;
}

static int tws_DoRouting(Tcl_Interp *interp, tws_router_t *router_ptr, tws_conn_t *conn, Tcl_Obj *const req_dict_ptr) {
    DBG(fprintf(stderr, "DoRouting\n"));

    Tcl_Obj *ctx_dict_ptr = Tcl_NewDictObj();
    Tcl_IncrRefCount(ctx_dict_ptr);

    if (TCL_OK != Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("router", -1), Tcl_NewStringObj(router_ptr->handle, -1))) {
        Tcl_DecrRefCount(ctx_dict_ptr);
        SetResult("router_process_conn: dict put failed");
        return TCL_ERROR;

    }
    if (TCL_OK != Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("server", -1), Tcl_NewStringObj(conn->accept_ctx->server->handle, -1))) {
        Tcl_DecrRefCount(ctx_dict_ptr);
        SetResult("router_process_conn: dict put failed");
        return TCL_ERROR;
    }
    if (TCL_OK != Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("conn", -1), Tcl_NewStringObj(conn->handle, -1))) {
        Tcl_DecrRefCount(ctx_dict_ptr);
        SetResult("router_process_conn: dict put failed");
        return TCL_ERROR;
    }
    if (TCL_OK != Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("addr", -1), Tcl_NewStringObj(conn->client_ip, -1))) {
        Tcl_DecrRefCount(ctx_dict_ptr);
        SetResult("router_process_conn: dict put failed");
        return TCL_ERROR;
    }
    if (TCL_OK != Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("port", -1), Tcl_NewIntObj(conn->accept_ctx->port))) {
        Tcl_DecrRefCount(ctx_dict_ptr);
        SetResult("router_process_conn: dict put failed");
        return TCL_ERROR;
    }
    if (TCL_OK != Tcl_DictObjPut(interp, ctx_dict_ptr, Tcl_NewStringObj("isSecureProto", -1), Tcl_NewBooleanObj(!conn->accept_ctx->option_http))) {
        Tcl_DecrRefCount(ctx_dict_ptr);
        SetResult("router_process_conn: dict put failed");
        return TCL_ERROR;
    }

    tws_route_t *route_ptr = router_ptr->firstRoutePtr;
    while (route_ptr != NULL) {
        int matched = 0;
        if (TCL_OK != tws_MatchRoute(interp, route_ptr, req_dict_ptr, &matched)) {
            Tcl_DecrRefCount(ctx_dict_ptr);
            SetResult("router_process_conn: match_route failed");
            return TCL_ERROR;
        }

        if (matched) {
            if (TCL_OK != tws_ProcessRoute(interp, conn, router_ptr, route_ptr, ctx_dict_ptr, req_dict_ptr)) {
                Tcl_DecrRefCount(ctx_dict_ptr);
//                SetResult("router_process_conn: process_route failed");
                return TCL_ERROR;
            }
            break;
        }
        route_ptr = route_ptr->nextPtr;
    }

    tws_DecrRefCountUntilZero(ctx_dict_ptr);

    if (route_ptr == NULL) {
        tws_CloseConn(conn, 1);
    }

    return TCL_OK;
}

int tws_HandleRouteEventInThread(tws_router_t *router, tws_conn_t *conn) {

    DBG(fprintf(stderr, "HandleRouteEventInThread: %s\n", conn->handle));
    tws_thread_data_t *dataPtr = (tws_thread_data_t *) Tcl_GetThreadData(conn->dataKeyPtr, sizeof(tws_thread_data_t));

    // no need to decr ref count of req_dict_ptr because it is already decr ref counted in DoRouting
    if (TCL_OK != tws_DoRouting(dataPtr->interp, router, conn, conn->requestDictPtr)) {
        DBG(fprintf(stderr, "DoRouting failed: %s\n", Tcl_GetString(Tcl_GetObjResult(dataPtr->interp))));
        Tcl_Obj *return_options_dict_ptr = Tcl_GetReturnOptions(dataPtr->interp, TCL_ERROR);
        Tcl_Obj *errorinfo_ptr;
        Tcl_Obj *errorinfo_key_ptr = Tcl_NewStringObj("-errorinfo", -1);
        Tcl_IncrRefCount(errorinfo_key_ptr);
        if (TCL_OK != Tcl_DictObjGet(dataPtr->interp, return_options_dict_ptr, Tcl_NewStringObj("-errorinfo", -1),
                                     &errorinfo_ptr)) {
            Tcl_DecrRefCount(errorinfo_key_ptr);
            tws_CloseConn(conn, 1);
            return 1;
        }
        Tcl_DecrRefCount(errorinfo_key_ptr);

        fprintf(stderr, "DoRouting: errorinfo: %s\n", Tcl_GetString(errorinfo_ptr));

        if (TCL_OK != tws_ReturnError(dataPtr->interp, conn, 500, "Internal Server Error", Tcl_GetEncoding(dataPtr->interp, "utf-8"))) {
            tws_CloseConn(conn, 1);
            return 1;
        }

        // close not needed here as ReturnError will close the connection after it writes the response
        return 1;
    }

//    conn->requestDictPtr = NULL;
    DBG(fprintf(stderr, "DoRouting done\n"));
    return 1;
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

    tws_HandleRouteEventInThread(router_ptr, conn);
    return TCL_OK;
}

static int tws_DestroyRouter(Tcl_Interp *interp, const char *handle) {
    DBG(fprintf(stderr, "DestroyRouter: %s\n", handle));
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
    while(route) {
        tws_route_t *next = route->nextPtr;
        Tcl_DecrRefCount(route->keys);
        Tcl_Free(route->pattern);
        Tcl_Free((char *) route);
        route = next;
    }

    tws_middleware_t *middleware = router_ptr->firstMiddlewarePtr;
    while(middleware) {
        tws_middleware_t *next = middleware->nextPtr;
        if (middleware->enter_proc_ptr) {
            tws_DecrRefCountUntilZero(middleware->enter_proc_ptr);
        }
        if (middleware->leave_proc_ptr) {
            tws_DecrRefCountUntilZero(middleware->leave_proc_ptr);
        }
        Tcl_Free((char *) middleware);
        middleware = next;
    }

    Tcl_Free((char *) router_ptr);

    fprintf(stderr, "router destroyed\n");

    return TCL_OK;
}

static char VAR_READ_ONLY_MSG[] = "var is read-only";

char *tws_VarTraceProc(ClientData clientData, Tcl_Interp *interp, const char *name1, const char *name2, int flags) {
    tws_trace_t *trace = (tws_trace_t *) clientData;
    if (trace->item == NULL) {
        DBG(fprintf(stderr, "VarTraceProc: router has been deleted\n"));
        if (!Tcl_InterpDeleted(trace->interp)) {
            Tcl_UntraceVar(trace->interp, trace->varname, TCL_TRACE_WRITES|TCL_TRACE_UNSETS,
                           (Tcl_VarTraceProc*) tws_VarTraceProc,
                           (ClientData) clientData);
        }
        Tcl_Free((char *) trace->varname);
        Tcl_Free((char *) trace);
        return NULL;
    }
    if (flags & TCL_TRACE_WRITES) {
        DBG(fprintf(stderr, "VarTraceProc: TCL_TRACE_WRITES\n"));
        Tcl_SetVar2(trace->interp, name1, name2, ((tws_router_t *) trace->item)->handle, TCL_LEAVE_ERR_MSG);
        return VAR_READ_ONLY_MSG;
    }
    if (flags & TCL_TRACE_UNSETS) {
        DBG(fprintf(stderr, "VarTraceProc: TCL_TRACE_UNSETS\n"));
        tws_DestroyRouter(trace->interp, ((tws_router_t *) trace->item)->handle);
        Tcl_Free((char *) trace->varname);
        Tcl_Free((char *) trace);
    }
    return NULL;
}

int tws_CreateRouterCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "CreateCmd\n"));
    CheckArgs(1, 2, 1, "?varname?");

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

    if (objc == 2) {
        tws_trace_t *trace = (tws_trace_t *) Tcl_Alloc(sizeof(tws_trace_t));
        trace->interp = interp;
        trace->varname = tws_strndup(Tcl_GetString(objv[1]), 80);
        trace->item = router_ptr;
        const char *objVar = Tcl_GetString(objv[1]);
        Tcl_UnsetVar(interp, objVar, 0);
        Tcl_SetVar  (interp, objVar, router_ptr->handle, 0);
        Tcl_TraceVar(interp,objVar,TCL_TRACE_WRITES|TCL_TRACE_UNSETS,
                     (Tcl_VarTraceProc*) tws_VarTraceProc,
                     (ClientData) trace);
    }

    SetResult(router_ptr->handle);
    return TCL_OK;

}

int tws_AddRouteCmd(ClientData clientData, Tcl_Interp *interp, int incoming_objc, Tcl_Obj *const objv[]) {
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
    Tcl_Size objc = incoming_objc;
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
    Tcl_Size http_method_len;
    const char *http_method = Tcl_GetStringFromObj(remObjv[2], &http_method_len);
    Tcl_Size path_len;
    const char *path = Tcl_GetStringFromObj(remObjv[3], &path_len);
    Tcl_Size proc_name_len;
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


int tws_AddMiddlewareCmd(ClientData clientData, Tcl_Interp *interp, int incoming_objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "AddMiddlewareCmd\n"));

    const char *enter_proc = NULL;
    const char *leave_proc = NULL;
    Tcl_ArgvInfo ArgTable[] = {
            {TCL_ARGV_STRING, "-enter_proc", NULL, &enter_proc, "enter proc"},
            {TCL_ARGV_STRING, "-leave_proc", NULL, &leave_proc, "leave proc"},
            {TCL_ARGV_END, NULL,             NULL, NULL, NULL}
    };
    Tcl_Obj **remObjv;
    Tcl_Size objc = incoming_objc;
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

    if (enter_proc && strlen(enter_proc) > 0) {
        DBG(fprintf(stderr, "enter_proc: %s (%ld)\n", enter_proc, strlen(enter_proc)));
        middleware_ptr->enter_proc_ptr = Tcl_NewStringObj(enter_proc, -1);
        Tcl_IncrRefCount(middleware_ptr->enter_proc_ptr);
    } else {
        middleware_ptr->enter_proc_ptr = NULL;
    }

    if (leave_proc && strlen(leave_proc) > 0) {
        DBG(fprintf(stderr, "leave_proc: %s (%ld)\n", leave_proc, strlen(leave_proc)));
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