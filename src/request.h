/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#ifndef TWEBSERVER_REQUEST_H
#define TWEBSERVER_REQUEST_H

#include <tcl.h>
#include "common.h"

int tws_UrlEncode(Tcl_Interp *interp, int enc_flags, const char *value, Tcl_Size value_length, Tcl_Obj **valuePtrPtr);
int tws_UrlDecode(Tcl_Interp *interp, Tcl_Encoding encoding, const char *value, Tcl_Size value_length, Tcl_Obj *resultPtr);
int tws_ParseRequest(Tcl_Interp *interp, Tcl_Encoding encoding, Tcl_DString *dsPtr, Tcl_Obj *dictPtr, Tcl_Size *offset);
int tws_ParseConnectionKeepalive(Tcl_Interp *interp, Tcl_Obj *headersPtr, int *keepalive);
int tws_ParseAcceptEncoding(Tcl_Interp *interp, Tcl_Obj *headersPtr, tws_compression_method_t *compression);
int tws_ParseBody(Tcl_Interp *interp, const char *curr, const char *end, Tcl_Obj *headersPtr, Tcl_Obj *result_ptr);
int tws_ParseTopPart(Tcl_Interp *interp, tws_conn_t *conn);
int tws_ParseBottomPart(Tcl_Interp *interp, tws_conn_t *conn, Tcl_Obj *req_dict_ptr);
int tws_ParseQueryStringParameters(Tcl_Interp *interp, Tcl_Encoding encoding, Tcl_Obj *queryStringPtr, Tcl_Obj *resultPtr);

#endif //TWEBSERVER_REQUEST_H
