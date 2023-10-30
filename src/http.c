/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include <unistd.h>
#include "http.h"

int tws_ReadHttpConnAsync(tws_conn_t *conn, Tcl_DString *dsPtr, int size) {
    long max_request_read_bytes = conn->accept_ctx->server->max_request_read_bytes;
    int max_buffer_size =
            size == 0 ? conn->accept_ctx->server->max_read_buffer_size : MIN(size, conn->accept_ctx->server->max_read_buffer_size);

    char *buf = (char *) Tcl_Alloc(max_buffer_size);
    int total_read = 0;
    int bytes_read = 0;

    int rc;
    for (;;) {
        rc = read(conn->client, buf, max_buffer_size);
        if (rc > 0) {
            bytes_read = rc;
            Tcl_DStringAppend(dsPtr, buf, bytes_read);
            total_read += bytes_read;
            if (total_read > max_request_read_bytes) {
                Tcl_Free(buf);
                return TWS_ERROR;
            }
            if (total_read < size) {
                continue;
            }
            if (total_read == size) {
                Tcl_Free(buf);
                return TWS_DONE;
            }

        } else {
            if (rc == 0) {
                Tcl_Free(buf);
                return TWS_DONE;
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    Tcl_Free(buf);
                    return TWS_AGAIN;
                } else {
                    Tcl_Free(buf);
                    return TWS_ERROR;
                }
            }
        }
    }
}

int tws_WriteHttpConnAsync(tws_conn_t *conn, const char *buf, int len) {
    int rc = write(conn->client, buf, len);
    if (rc == len) {
        return TWS_DONE;
    } else {
        if (rc == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return TWS_AGAIN;
            } else {
                return TWS_ERROR;
            }
        } else {
            return TWS_AGAIN;
        }
    }
}