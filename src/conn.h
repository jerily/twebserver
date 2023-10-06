/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#ifndef TWEBSERVER_CONN_H
#define TWEBSERVER_CONN_H

#include <tcl.h>
#include "common.h"

ObjCmdProc(tws_ReadConnCmd);
ObjCmdProc(tws_WriteConnCmd);
ObjCmdProc(tws_ParseConnCmd);
ObjCmdProc(tws_ReturnConnCmd);
ObjCmdProc(tws_CloseConnCmd);
ObjCmdProc(tws_KeepaliveConnCmd);
ObjCmdProc(tws_InfoConnCmd);

int tws_Listen(Tcl_Interp *interp, const char *handle, Tcl_Obj *portPtr);
int tws_ParseConn(Tcl_Interp *interp, tws_conn_t *conn, const char *conn_handle, Tcl_Encoding encoding, Tcl_Obj **requestDictPtr);

#endif //TWEBSERVER_CONN_H
