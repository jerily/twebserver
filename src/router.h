/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#ifndef TWEBSERVER_ROUTER_H
#define TWEBSERVER_ROUTER_H

#include <tcl.h>

int tws_CreateRouterCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
int tws_AddRouteCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

#endif //TWEBSERVER_ROUTER_H
