/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
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
tws_server_t *tws_GetCurrentServer();
int tws_HandleTermEventInThread(Tcl_Event *evPtr, int flags);
void tws_QueueConnEvent(tws_conn_t *conn, Tcl_EventProc *proc);
void tws_WaitForConn(tws_conn_t *conn, int mask, Tcl_EventProc *proc);
void tws_CancelConnIO(tws_conn_t *conn);
void tws_StartConnTimer(tws_conn_t *conn, int reading);
void tws_KeepaliveConn(tws_conn_t *conn);

#endif //TWEBSERVER_CONN_H
