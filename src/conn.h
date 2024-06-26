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

#endif //TWEBSERVER_CONN_H
