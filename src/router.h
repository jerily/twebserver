/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#ifndef TWEBSERVER_ROUTER_H
#define TWEBSERVER_ROUTER_H

#include <tcl.h>

ObjCmdProc(tws_CreateRouterCmd);
ObjCmdProc(tws_AddRouteCmd);
ObjCmdProc(tws_InfoRoutesCmd);
ObjCmdProc(tws_AddMiddlewareCmd);
int tws_HandleRouteEventInThread(tws_router_t *router, tws_conn_t *conn, Tcl_Obj *req_dict_ptr);
int tws_CreateContextDict(Tcl_Interp *interp, tws_conn_t *conn, Tcl_Obj **result_ptr);

#endif //TWEBSERVER_ROUTER_H
