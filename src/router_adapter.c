/* Copyright Jerily LTD. All Rights Reserved.
 * SPDX-License-Identifier: MIT.
 */
#include "router_adapter.h"

#include <limits.h>
#include <string.h>

static int dict_get(Tcl_Interp *interp, Tcl_Obj *dict, const char *name,
                    int required, Tcl_Obj **value) {
    Tcl_Obj *key = Tcl_NewStringObj(name, -1);
    Tcl_IncrRefCount(key);
    int rc = Tcl_DictObjGet(interp, dict, key, value);
    Tcl_DecrRefCount(key);
    if (rc == TCL_OK && required && *value == NULL) {
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("missing required field: %s", name));
        return TCL_ERROR;
    }
    return rc;
}

/* The private list keeps the argument vector alive during recursive callbacks.
 * Evaluate objects directly so command-prefix arguments remain literal. */
static int invoke_prefix(Tcl_Interp *interp, Tcl_Obj *prefix, int extra_count,
                         Tcl_Obj *const extra[]) {
    Tcl_Obj *command = Tcl_DuplicateObj(prefix);
    Tcl_IncrRefCount(command);
    Tcl_Size count;
    Tcl_Obj **args;
    int rc = Tcl_ListObjLength(interp, command, &count);
    if (rc == TCL_OK && count == 0) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("handler command prefix must not be empty", -1));
        rc = TCL_ERROR;
    }
    for (int i = 0; rc == TCL_OK && i < extra_count; ++i) {
        rc = Tcl_ListObjAppendElement(interp, command, extra[i]);
    }
    if (rc == TCL_OK) {
        rc = Tcl_ListObjGetElements(interp, command, &count, &args);
    }
    if (rc == TCL_OK && count > INT_MAX) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("too many handler arguments", -1));
        rc = TCL_ERROR;
    }
    if (rc == TCL_OK) {
        rc = Tcl_EvalObjv(interp, (int) count, args, TCL_EVAL_GLOBAL);
    }
    Tcl_DecrRefCount(command);
    return rc;
}

/* Adapt legacy handler arguments. Routing and middleware belong to tpathexp. */
int tws_InvokeHandlerCmd(ClientData clientData, Tcl_Interp *interp, int objc,
                         Tcl_Obj *const objv[]) {
    UNUSED(clientData);
    CheckArgs(5, 5, 1, "handler request context params");
    Tcl_Obj *args[] = {objv[3], objv[2]};
    return invoke_prefix(interp, objv[1], 2, args);
}

static void log_dispatch_error(Tcl_Interp *interp, int code) {
    Tcl_Obj *options = Tcl_GetReturnOptions(interp, code);
    Tcl_Obj *detail = NULL;
    Tcl_IncrRefCount(options);
    dict_get(interp, options, "-errorinfo", 0, &detail);
    if (detail == NULL) detail = Tcl_GetObjResult(interp);
    Tcl_Channel channel = Tcl_GetStdChannel(TCL_STDERR);
    if (channel != NULL) {
        Tcl_WriteObj(channel, detail);
        Tcl_WriteChars(channel, "\n", 1);
        Tcl_Flush(channel);
    }
    Tcl_DecrRefCount(options);
}

int tws_RouterProcessConnCmd(ClientData clientData, Tcl_Interp *interp, int objc,
                            Tcl_Obj *const objv[]) {
    UNUSED(clientData);
    CheckArgs(4, 4, 1, "router context request");

    Tcl_Obj *req = Tcl_DuplicateObj(objv[3]);
    Tcl_Obj *method, *res, *conn;
    Tcl_IncrRefCount(req);
    int head = 0;
    int rc = dict_get(interp, req, "httpMethod", 1, &method);
    if (rc == TCL_OK) {
        Tcl_Size length;
        const char *text = Tcl_GetStringFromObj(method, &length);
        head = length == 4 && memcmp(text, "HEAD", 4) == 0;
        rc = Tcl_DictObjPut(interp, req, Tcl_NewStringObj("method", -1), method);
    }
    if (rc == TCL_OK) {
        Tcl_Obj *dispatch = Tcl_NewStringObj("dispatch", -1);
        Tcl_Obj *args[] = {objv[1], dispatch, req, objv[2]};
        Tcl_IncrRefCount(dispatch);
        rc = Tcl_EvalObjv(interp, 4, args, TCL_EVAL_GLOBAL);
        Tcl_DecrRefCount(dispatch);
    }
    if (rc == TCL_OK) {
        res = Tcl_DuplicateObj(Tcl_GetObjResult(interp));
        Tcl_IncrRefCount(res);
    } else {
        log_dispatch_error(interp, rc);
        Tcl_ResetResult(interp);
        res = Tcl_NewDictObj();
        Tcl_IncrRefCount(res);
        Tcl_Obj *headers = Tcl_NewDictObj();
        Tcl_DictObjPut(interp, headers, Tcl_NewStringObj("Content-Type", -1),
                       Tcl_NewStringObj("text/plain", -1));
        Tcl_DictObjPut(interp, res, Tcl_NewStringObj("statusCode", -1), Tcl_NewIntObj(500));
        Tcl_DictObjPut(interp, res, Tcl_NewStringObj("headers", -1), headers);
        Tcl_DictObjPut(interp, res, Tcl_NewStringObj("body", -1),
                       Tcl_NewStringObj("Internal Server Error", -1));
        rc = TCL_OK;
    }
    if (head) {
        rc = Tcl_DictObjPut(interp, res, Tcl_NewStringObj("body", -1), Tcl_NewObj());
    }
    if (rc == TCL_OK) rc = dict_get(interp, objv[2], "conn", 1, &conn);
    if (rc == TCL_OK) {
        /* Keep the ordinary response command as the transport boundary. */
        Tcl_Obj *send = Tcl_NewStringObj("::twebserver::return_response", -1);
        Tcl_Obj *args[] = {send, conn, res};
        Tcl_IncrRefCount(send);
        rc = Tcl_EvalObjv(interp, 3, args, TCL_EVAL_GLOBAL);
        Tcl_DecrRefCount(send);
    }
    Tcl_DecrRefCount(res);
    Tcl_DecrRefCount(req);
    return rc;
}
