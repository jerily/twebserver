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

/* All state is per invocation: callbacks may recursively dispatch, change
 * application configuration, or delete the router that selected this handler. */
int tws_InvokeHandlerCmd(ClientData clientData, Tcl_Interp *interp, int objc,
                         Tcl_Obj *const objv[]) {
    UNUSED(clientData);
    CheckArgs(7, 7, 1, "handler middleware guards request context params");

    Tcl_Obj *middleware = Tcl_DuplicateObj(objv[2]);
    Tcl_Obj *guards = Tcl_DuplicateObj(objv[3]);
    Tcl_Obj *req = objv[4];
    Tcl_Obj *ctx = objv[5];
    Tcl_Obj *leaves = Tcl_NewListObj(0, NULL);
    Tcl_Obj *res = NULL;
    Tcl_IncrRefCount(middleware);
    Tcl_IncrRefCount(guards);
    Tcl_IncrRefCount(req);
    Tcl_IncrRefCount(leaves);

    Tcl_Size count;
    int rc = Tcl_ListObjLength(interp, middleware, &count);
    if (rc != TCL_OK) goto failed;
    for (Tcl_Size i = 0; i < count; ++i) {
        Tcl_Obj *layer, *enter, *leave;
        if (Tcl_ListObjIndex(interp, middleware, i, &layer) != TCL_OK ||
            Tcl_ListObjIndex(interp, layer, 0, &enter) != TCL_OK ||
            Tcl_ListObjIndex(interp, layer, 1, &leave) != TCL_OK) {
            rc = TCL_ERROR;
            goto failed;
        }
        /* Include this layer when its enter hook returns an HTTP response. */
        if (leave != NULL && Tcl_GetCharLength(leave) != 0) {
            rc = Tcl_ListObjAppendElement(interp, leaves, leave);
            if (rc != TCL_OK) goto failed;
        }
        if (enter != NULL && Tcl_GetCharLength(enter) != 0) {
            Tcl_Obj *args[] = {ctx, req};
            rc = invoke_prefix(interp, enter, 2, args);
            if (rc != TCL_OK) goto failed;
            Tcl_Obj *next = Tcl_GetObjResult(interp);
            Tcl_IncrRefCount(next);
            Tcl_DecrRefCount(req);
            req = next;
        }
    }

    rc = Tcl_ListObjLength(interp, guards, &count);
    if (rc != TCL_OK) goto failed;
    for (Tcl_Size i = 0; i < count; ++i) {
        Tcl_Obj *guard;
        rc = Tcl_ListObjIndex(interp, guards, i, &guard);
        if (rc != TCL_OK) goto failed;
        Tcl_Obj *args[] = {ctx, req};
        rc = invoke_prefix(interp, guard, 2, args);
        if (rc != TCL_OK) goto failed;
        Tcl_Obj *next = Tcl_GetObjResult(interp);
        Tcl_IncrRefCount(next);
        Tcl_DecrRefCount(req);
        req = next;
    }

    /* tpathexp already populated req.pathParameters; objv[6] supplies the same
     * captures separately for its standard request/context/params convention. */
    Tcl_Obj *args[] = {ctx, req};
    rc = invoke_prefix(interp, objv[1], 2, args);
    if (rc != TCL_OK) goto failed;
    res = Tcl_GetObjResult(interp);
    Tcl_IncrRefCount(res);
    goto leave;

failed:
    if (rc == TCL_ERROR) {
        Tcl_Obj *options = Tcl_GetReturnOptions(interp, rc);
        Tcl_Obj *status, *body;
        Tcl_IncrRefCount(options);
        if (dict_get(interp, options, "statusCode", 0, &status) == TCL_OK &&
            dict_get(interp, options, "body", 0, &body) == TCL_OK &&
            status != NULL && body != NULL) {
            res = options;
            Tcl_ResetResult(interp);
            rc = TCL_OK;
            goto leave;
        }
        Tcl_DecrRefCount(options);
    }
    /* Preserve the error and its return options. Ordinary errors skip leaves. */
    goto done;

leave:
    Tcl_ListObjLength(interp, leaves, &count);
    for (Tcl_Size i = count; i > 0; --i) {
        Tcl_Obj *hook;
        Tcl_ListObjIndex(interp, leaves, i - 1, &hook);
        Tcl_Obj *leave_args[] = {ctx, req, res};
        rc = invoke_prefix(interp, hook, 3, leave_args);
        if (rc != TCL_OK) goto done;
        Tcl_Obj *next = Tcl_GetObjResult(interp);
        Tcl_IncrRefCount(next);
        Tcl_DecrRefCount(res);
        res = next;
    }
    Tcl_SetObjResult(interp, res);

done:
    if (res != NULL) Tcl_DecrRefCount(res);
    Tcl_DecrRefCount(leaves);
    Tcl_DecrRefCount(req);
    Tcl_DecrRefCount(guards);
    Tcl_DecrRefCount(middleware);
    return rc;
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
