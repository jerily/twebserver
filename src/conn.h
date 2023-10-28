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
int tws_ReturnConn(Tcl_Interp *interp, tws_conn_t *conn, Tcl_Obj *responseDictPtr, Tcl_Encoding encoding);
int tws_CloseConn(tws_conn_t *conn, int force);
int tws_ReadConnAsync(Tcl_Interp *interp, tws_conn_t *conn, Tcl_DString *dsPtr, int size);

#endif //TWEBSERVER_CONN_H
