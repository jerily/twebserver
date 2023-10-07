/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#include "common.h"
#include "conn.h"
#include "router.h"
#include "path_regexp/path_regexp.h"
#include <string.h>

static int tws_MatchRoute(Tcl_Interp *interp, tws_route_t *route_ptr, Tcl_Obj *requestDictPtr, int *flag) {
    Tcl_Obj *http_method_key_ptr = Tcl_NewStringObj("httpMethod", -1);
    Tcl_IncrRefCount(http_method_key_ptr);
    Tcl_Obj *http_method_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, requestDictPtr, http_method_key_ptr, &http_method_ptr)) {
        Tcl_DecrRefCount(http_method_key_ptr);
        SetResult("router_process_conn: dict get failed");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(http_method_key_ptr);
    int http_method_len;
    const char *http_method = Tcl_GetStringFromObj(http_method_ptr, &http_method_len);

    Tcl_Obj *path_key_ptr = Tcl_NewStringObj("path", -1);
    Tcl_IncrRefCount(path_key_ptr);
    Tcl_Obj *path_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, requestDictPtr, path_key_ptr, &path_ptr)) {
        Tcl_DecrRefCount(path_key_ptr);
        SetResult("router_process_conn: dict get failed");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(path_key_ptr);
    int path_len;
    const char *path = Tcl_GetStringFromObj(path_ptr, &path_len);

    // TODO: make this more sophisticated with regexp matching and path parameters parsing
    if (http_method_len == route_ptr->http_method_len
            && path_len == route_ptr->path_len
            && strncmp(http_method, route_ptr->http_method, route_ptr->http_method_len) == 0
            && strncmp(path, route_ptr->path, route_ptr->path_len) == 0) {
        *flag = 1;
    } else {
        *flag = 0;
    }

    return TCL_OK;
}

static int tws_EvalRoute(Tcl_Interp *interp, tws_route_t *route_ptr, Tcl_Obj *req_dict_ptr, Tcl_Obj *res_dict_ptr) {

    Tcl_Obj *proc_name_ptr = Tcl_NewStringObj(route_ptr->proc_name, -1);
    Tcl_IncrRefCount(proc_name_ptr);
    Tcl_Obj *req_var = Tcl_NewStringObj("reqDict", -1);
    Tcl_IncrRefCount(req_var);
    Tcl_Obj *res_var = Tcl_NewStringObj("resDict", -1);
    Tcl_IncrRefCount(res_var);

    Tcl_ObjSetVar2(interp, req_var, NULL, req_dict_ptr, TCL_GLOBAL_ONLY);
    Tcl_ObjSetVar2(interp, res_var, NULL, res_dict_ptr, TCL_GLOBAL_ONLY);

    Tcl_Obj *const proc_objv[] = {proc_name_ptr, req_var, res_var};
    if (TCL_OK != Tcl_EvalObjv(interp, 3, proc_objv, TCL_EVAL_GLOBAL)) {
        Tcl_DecrRefCount(proc_name_ptr);
        SetResult("router_process_conn: eval failed");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(proc_name_ptr);
    return TCL_OK;
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
    Tcl_Encoding encoding = Tcl_GetEncoding(interp, "utf-8");
    Tcl_Obj *req_dict_ptr;
    if (TCL_OK != tws_ParseConn(interp, conn, conn_handle, encoding, &req_dict_ptr)) {
        SetResult("router_process_conn: parse_conn failed");
        return TCL_ERROR;
    }

    Tcl_Obj *res_dict_ptr = Tcl_NewDictObj();
    tws_route_t *route_ptr = router_ptr->firstRoutePtr;
    while (route_ptr != NULL) {
        int matched;
        if (TCL_OK != tws_MatchRoute(interp, route_ptr, req_dict_ptr, &matched)) {
            SetResult("router_process_conn: match_route failed");
            return TCL_ERROR;
        }
        if (matched) {
            if (TCL_OK != tws_EvalRoute(interp, route_ptr, req_dict_ptr, res_dict_ptr)) {
                SetResult("router_process_conn: eval route failed");
                return TCL_ERROR;
            }
            if (TCL_OK != tws_ReturnConn(interp, conn, res_dict_ptr, encoding)) {
                SetResult("router_process_conn: return_conn failed");
                return TCL_ERROR;
            }
            if (TCL_OK != tws_CloseConn(conn, 0)) {
                SetResult("router_process_conn: close_conn failed");
                return TCL_ERROR;
            }
            break;
        }
        route_ptr = route_ptr->nextPtr;
    }

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
    CheckArgs(5, 5, 1, "router_handle http_method path proc_name");
    tws_router_t *router_ptr = tws_GetInternalFromRouterName(Tcl_GetString(objv[1]));
    if (!router_ptr) {
        SetResult("add_route: router handle not found");
        return TCL_ERROR;
    }
    int http_method_len;
    const char *http_method = Tcl_GetStringFromObj(objv[2], &http_method_len);
    int path_len;
    const char *path = Tcl_GetStringFromObj(objv[3], &path_len);
    int proc_name_len;
    const char *proc_name = Tcl_GetStringFromObj(objv[4], &proc_name_len);

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

    // todo: pass options like pathMatch = prefix | full
    if (TCL_OK != tws_PathToRegExp(interp, path, path_len, &route_ptr->regexp)) {
        SetResult("add_route: path_to_regexp failed");
        return TCL_ERROR;
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
