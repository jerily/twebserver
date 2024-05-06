/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#ifndef TWEBSERVER_RETURN_H
#define TWEBSERVER_RETURN_H

#include "common.h"

int tws_ReturnConn(Tcl_Interp *interp, tws_conn_t *conn, Tcl_Obj *responseDictPtr, Tcl_Encoding encoding);
int tws_CloseConn(tws_conn_t *conn, int force);
int tws_CleanupConnections();

#endif //TWEBSERVER_RETURN_H