/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#include "common.h"
#include "conn.h"
#include "router.h"
#include <string.h>

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

    char handle[30];
    CMD_ROUTER_NAME(handle, router_ptr);
    tws_RegisterRouterName(handle, router_ptr);

    SetResult(handle);
    return TCL_OK;

}

int tws_RouterProcessConnCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "RouterProcessConnCmd\n"));
    CheckArgs(3, 3, 1, "conn_handle addr port");

    tws_router_t *router_ptr = (tws_router_t *) clientData;

    const char *conn_handle = Tcl_GetString(objv[1]);
    tws_conn_t *conn = tws_GetInternalFromConnName(conn_handle);
    if (!conn) {
        SetResult("router_process_conn: conn handle not found");
        return TCL_ERROR;
    }
    Tcl_Encoding encoding = Tcl_GetEncoding(interp, "utf-8");
    Tcl_Obj *requestDictPtr;
    tws_ParseConn(interp, conn, conn_handle, encoding, &requestDictPtr);

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

    memcpy(route_ptr->http_method, http_method, http_method_len);
    route_ptr->http_method[http_method_len] = '\0';
    memcpy(route_ptr->path, path, path_len);
    route_ptr->path[path_len] = '\0';
    memcpy(route_ptr->proc_name, proc_name, proc_name_len);
    route_ptr->proc_name[proc_name_len] = '\0';
    route_ptr->nextPtr = NULL;

    if (router_ptr->firstRoutePtr == NULL) {
        router_ptr->firstRoutePtr = route_ptr;
        router_ptr->lastRoutePtr = route_ptr;
    } else {
        router_ptr->lastRoutePtr->nextPtr = route_ptr;
        router_ptr->lastRoutePtr = route_ptr;
    }

    Tcl_CreateObjCommand(interp, router_ptr->handle, tws_RouterProcessConnCmd, (ClientData) router_ptr, NULL);
    return TCL_OK;
}
