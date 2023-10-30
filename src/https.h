/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#ifndef TWEBSERVER_HTTPS_H
#define TWEBSERVER_HTTPS_H

#include <tcl.h>
#include "common.h"

int tws_ClientHelloCallback(SSL *ssl, int *al, void *arg);
int tws_CreateSslContext(Tcl_Interp *interp, SSL_CTX **sslCtx);
int tws_ConfigureSslContext(Tcl_Interp *interp, SSL_CTX *ctx, const char *key_file, const char *cert_file);
int tws_ReadSslConnAsync(tws_conn_t *conn, Tcl_DString *dsPtr, int size);
int tws_WriteSslConnAsync(tws_conn_t *conn, const char *buf, int len);

#endif //TWEBSERVER_HTTPS_H
