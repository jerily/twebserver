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
int tws_UrlDecode(Tcl_Encoding encoding, const char *value, Tcl_Size value_length, Tcl_DString *value_ds_ptr, int *error_num);
int tws_ParseRequest(tws_conn_t *conn, int *error_num);
int tws_ParseConnectionKeepalive(Tcl_HashTable *headers_HT_ptr, int *keepalive);
int tws_ParseAcceptEncoding(Tcl_HashTable *headers_HT_ptr, tws_compression_method_t *compression);
int tws_ParseBody(tws_conn_t *conn, const char *curr, const char *end, int *error_num);
int tws_ParseTopPart(tws_conn_t *conn, int *error_num);
int tws_ParseBottomPart(tws_conn_t *conn, int *error_num);
int tws_ParseQueryStringParameters(Tcl_Encoding encoding, const char *query_string, Tcl_Size query_string_length, Tcl_DString *parse_ds_ptr, int *error_num);

#define ERROR_PATH_URL_DECODE 1
#define ERROR_NO_HTTP_METHOD 2
#define ERROR_INVALID_HTTP_METHOD 3
#define ERROR_NO_URL 4
#define ERROR_NO_HTTP_VERSION 5
#define ERROR_INVALID_HTTP_VERSION 6
#define ERROR_NO_HEADER_KEY 7
#define ERROR_URLDECODE_INVALID_SEQUENCE 8
#define ERROR_BASE64_ENCODE_BODY 9

static const char *tws_parse_error_messages[] = {
        "OK",
        "Path URL decode error",
        "No HTTP method found",
        "Invalid HTTP method",
        "No URL found",
        "No HTTP version found",
        "Invalid HTTP version",
        "No header key found",
        "URL decode invalid sequence",
        "Base64 encode request body"
};

#endif //TWEBSERVER_REQUEST_H
