/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#ifndef TWEBSERVER_CONN_H
#define TWEBSERVER_CONN_H

#include <tcl.h>
#include "common.h"
#include "https.h"
#include "http.h"

ObjCmdProc(tws_InfoConnCmd);

int tws_Listen(Tcl_Interp *interp, tws_server_t *server, int option_http, int option_num_threads, const char *host, const char *port);
int tws_ReturnConn(Tcl_Interp *interp, tws_conn_t *conn, Tcl_Obj *responseDictPtr, Tcl_Encoding encoding);
int tws_CloseConn(tws_conn_t *conn, int force);
tws_server_t *tws_GetCurrentServer();

#endif //TWEBSERVER_CONN_H
