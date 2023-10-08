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

#endif //TWEBSERVER_ROUTER_H
