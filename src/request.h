/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#ifndef TWEBSERVER_REQUEST_H
#define TWEBSERVER_REQUEST_H

#include <tcl.h>
#include "common.h"

ObjCmdProc(tws_ParseRequestCmd);

int tws_UrlEncode(Tcl_Interp *interp, int enc_flags, const char *value, int value_length, Tcl_Obj **valuePtrPtr);
int tws_UrlDecode(Tcl_Interp *interp, Tcl_Encoding encoding, const char *value, int value_length, Tcl_Obj *resultPtr);
int tws_ParseRequest(Tcl_Interp *interp, Tcl_Encoding encoding, Tcl_DString *dsPtr, Tcl_Obj *dictPtr, int *offset);
int tws_ParseConnectionKeepalive(Tcl_Interp *interp, Tcl_Obj *headersPtr, int *keepalive);
int tws_ParseAcceptEncoding(Tcl_Interp *interp, Tcl_Obj *headersPtr, tws_compression_method_t *compression);
int tws_ParseMultipartFormData(Tcl_Interp *interp, const char *body, int body_length, Tcl_Obj *multipart_boundary_ptr, Tcl_Obj *resultPtr);
int tws_ParseBody(Tcl_Interp *interp, const char *curr, const char *end, Tcl_Obj *headersPtr, Tcl_Obj *resultPtr);

#endif //TWEBSERVER_REQUEST_H
