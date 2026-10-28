/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include <errno.h>
#include <unistd.h>
#include "http.h"

int tws_ReadHttpConnAsync(tws_conn_t *conn, Tcl_DString *dsPtr, Tcl_Size size) {
    conn->io_mask = 0;
    Tcl_Size max_request_read_bytes = conn->accept_ctx->server->max_request_read_bytes - Tcl_DStringLength(&conn->inout_ds);
    Tcl_Size max_buffer_size =
            size == 0 ? conn->accept_ctx->server->max_read_buffer_size : MIN(size, conn->accept_ctx->server->max_read_buffer_size);

    char *buf = (char *) ckalloc(max_buffer_size);
    Tcl_Size total_read = 0;
    ssize_t rc;
    for (;;) {
        Tcl_Size toread = size == 0 ? max_buffer_size : MIN(max_buffer_size, size - total_read);
        rc = read(conn->client, buf, toread);

        if (rc > 0) {
            conn->latest_millis = current_time_in_millis();
            total_read += rc;
            if (total_read > max_request_read_bytes) {
                ckfree(buf);
                return TWS_ERROR;
            }
            Tcl_DStringAppend(dsPtr, buf, rc);
            if (total_read == size) {
                ckfree(buf);
                return TWS_DONE;
            }
            if (size == 0) {
                /* Let the parser examine this chunk before waiting for more. */
                ckfree(buf);
                return TWS_AGAIN;
            }

        } else {
            if (rc == 0) {
                DBG2(printf("peer closed connection %d\n", conn->client));
                ckfree(buf);
                return TWS_DONE;
            } else {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    conn->io_mask = TCL_READABLE;
                    ckfree(buf);
                    return TWS_AGAIN;
                } else {
                    DBG2(printf("read error: %d\n", conn->client));
                    ckfree(buf);
                    return TWS_ERROR;
                }
            }
        }
    }
}

int tws_WriteHttpConnAsync(tws_conn_t *conn, const char *buf, Tcl_Size len) {
    conn->io_mask = 0;
    Tcl_Size total_written = 0;
    ssize_t rc;
    while (total_written < len) {
        rc = write(conn->client, buf+total_written, len-total_written);
        if (rc > 0) {
            conn->latest_millis = current_time_in_millis();
            total_written += rc;
            if (total_written == len) {
                return TWS_DONE;
            }
        } else {
            if (rc == -1) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    conn->write_offset += total_written;
                    conn->io_mask = TCL_WRITABLE;
                    return TWS_AGAIN;
                } else {
                    return TWS_ERROR;
                }
            }
            /* A zero-byte write must not turn into a busy loop. */
            return TWS_ERROR;
        }
    }
    return TWS_DONE;
}
