/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#ifndef TWEBSERVER_HTTP_H
#define TWEBSERVER_HTTP_H

#include <tcl.h>
#include "common.h"

int tws_ReadHttpConnAsync(tws_conn_t *conn, Tcl_DString *dsPtr, int size);
int tws_WriteHttpConnAsync(tws_conn_t *conn, const char *buf, int len);

#endif //TWEBSERVER_HTTP_H
