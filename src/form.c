/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include "form.h"
#include "base64.h"
#include "request.h"


static int tws_ParseMultipartEntry(Tcl_Interp *interp, const char *bs, const char *be, Tcl_Obj *multipart_form_data_fields_ptr, Tcl_Obj *multipart_form_data_files_ptr) {
    // look for and parse the "field_name" from the "Content-Disposition" header for this part, e.g.:
    // "field1" from header ```Content-Disposition: form-data; name="field1"```
    // or:
    // "field2" from header ```Content-Disposition: form-data; name="field2"; filename="file1.txt"```

    // find "Content-Disposition" header
    const char *p = bs;
    while (p < be - 18 && !(p[0] == 'C' && p[1] == 'o' && p[2] == 'n' && p[3] == 't' && p[4] == 'e' && p[5] == 'n' && p[6] == 't' && p[7] == '-' && p[8] == 'D' && p[9] == 'i' && p[10] == 's' && p[11] == 'p' && p[12] == 'o' && p[13] == 's' && p[14] == 'i' && p[15] == 't' && p[16] == 'i' && p[17] == 'o' && p[18] == 'n')) {
        p++;
    }

    // skip Content-Disposition part
    if (p < be) {
        p += 19;
//            fprintf(stderr, "found Content-Disposition header\n");
    }

    // find "name="
    while (p < be - 5 && !(p[0] == 'n' && p[1] == 'a' && p[2] == 'm' && p[3] == 'e' && p[4] == '=')) {
        p++;
    }

    // skip "name="
    if (p < be) {
        p += 5;
//            fprintf(stderr, "found name=\n");
    }

    // extract "field_name" from "Content-Disposition" header and flag it as filename or normal field
    const char *field_name = NULL;
    const char *field_name_end = NULL;
    if (p < be) {
        // skip spaces
        while (p < be && CHARTYPE(space, *p) != 0) {
            p++;
        }
        // skip '"'
        if (p < be && *p == '"') {
            p++;
        }
        field_name = p;
        // find '"'
        while (p < be && *p != '"') {
            p++;
        }
        field_name_end = p;

        // skip '"'
        p++;
    }

//        fprintf(stderr, "field_name=%.*s\n", (int) (field_name_end - field_name), field_name);

    // check if it is a filename
    const char *filename = NULL;
    const char *filename_end = NULL;
    if (p < be) {
        // find "filename="
        while (p < be - 9 && !(p[0] == 'f' && p[1] == 'i' && p[2] == 'l' && p[3] == 'e' && p[4] == 'n' && p[5] == 'a' && p[6] == 'm' && p[7] == 'e' && p[8] == '=')) {
            p++;
        }

        // skip "filename="
        p += 9;

        // skip spaces
        while (p < be && CHARTYPE(space, *p) != 0) {
            p++;
        }
        // skip '"'
        if (p < be && *p == '"') {
            p++;
        }
        filename = p;
        // find '"'
        while (p < be && *p != '"') {
            p++;
        }
        filename_end = p;

        // skip '"'
        p++;
    }

//        fprintf(stderr, "filename=%.*s\n", (int) (filename_end - filename), filename);

    int filename_length = filename_end - filename;

    // extract and save the part body as base64-encoded string in "multipart_form_data_ptr" as key-value pairs

    // find the end of the part headers, they are denoted by "\r\n\r\n" or "\n\n"

    // find "\r\n\r\n" or "\n\n"
    const char *headers_end = bs;
    while (headers_end < be) {
        if (headers_end + 3 < be && headers_end[0] == '\r' && headers_end[1] == '\n' && headers_end[2] == '\r' && headers_end[3] == '\n') {
            headers_end += 4;
            break;
        } else if (headers_end + 1 < be && headers_end[0] == '\n' && headers_end[1] == '\n') {
            headers_end += 2;
            break;
        }
        headers_end++;
    }
    bs = headers_end;

    Tcl_Obj *value_ptr = NULL;
    if (filename_length > 0) {
        int block_length = be - bs;
        char *block_body = Tcl_Alloc(block_length * 2);
        size_t block_body_length;
        if (base64_encode(bs, block_length, block_body, &block_body_length)) {
            Tcl_Free(block_body);
            SetResult("tws_ParseMultipartFormData: base64_encode failed");
            return TCL_ERROR;
        }

        if (TCL_OK != Tcl_DictObjPut(interp, multipart_form_data_files_ptr, Tcl_NewStringObj(filename, filename_end - filename), Tcl_NewStringObj(block_body, block_body_length))) {
            Tcl_Free(block_body);
            SetResult("tws_ParseMultipartFormData: multipart/form-data dict write error");
            return TCL_ERROR;
        }

        value_ptr = Tcl_NewStringObj(filename, filename_length);
    } else {
        value_ptr = Tcl_NewStringObj(bs, be - bs);
    }

    if (TCL_OK != Tcl_DictObjPut(interp, multipart_form_data_fields_ptr, Tcl_NewStringObj(field_name, field_name_end - field_name), value_ptr)) {
        SetResult("tws_ParseMultipartFormData: multipart/form-data dict write error");
        return TCL_ERROR;
    }

    return TCL_OK;
}

static int tws_ParseMultipartFormData(Tcl_Interp *interp, const char *body, int body_length, Tcl_Obj *multipart_boundary_ptr, Tcl_Obj *resultPtr) {

    const char *end = body + body_length;

    // parse the multipart/form-data body
    int boundary_length;
    const char *boundary = Tcl_GetStringFromObj(multipart_boundary_ptr, &boundary_length);

    // find boundary start (bs)
    const char *bs = body;
    const char *end_minus_boundary_and_prefix = end - boundary_length - 2;
    while (bs < end_minus_boundary_and_prefix) {
        if (bs[0] == '-' && bs[1] == '-' && strncmp(bs + 2, boundary, boundary_length) == 0) {
            break;
        }
        bs++;
    }

    // skip the boundary
    bs += boundary_length + 2;

    // skip "\r\n" or "\n"
    if (bs + 1 < end && *bs == '\r' && *(bs + 1) == '\n') {
        bs += 2;
    } else if (bs < end && *bs == '\r') {
        bs++;
    } else if (bs < end && *bs == '\n') {
        bs++;
    }

    // extract all fields and files
    Tcl_Obj *multipart_form_data_fields_ptr = Tcl_NewDictObj();
    Tcl_IncrRefCount(multipart_form_data_fields_ptr);
    Tcl_Obj *multipart_form_data_files_ptr = Tcl_NewDictObj();
    Tcl_IncrRefCount(multipart_form_data_files_ptr);
    while (bs < end_minus_boundary_and_prefix) {
        // find boundary end (be)
        const char *be = bs;
        while (be < end_minus_boundary_and_prefix) {
            if (be[0] == '-' && be[1] == '-' && strncmp(be + 2, boundary, boundary_length) == 0) {
                break;
            }
            be++;
        }

        const char *next_bs = be;

        // skip "\r\n" or "\n" backwards
        if (be - 2 >= bs && be[-2] == '\r' && be[-1] == '\n') {
            be -= 2;
        } else if (be - 1 >= bs && be[-1] == '\n') {
            be -= 1;
        }

        if (be == bs) {
            Tcl_DecrRefCount(multipart_form_data_fields_ptr);
            Tcl_DecrRefCount(multipart_form_data_files_ptr);
            return TCL_OK;
        }

        if (TCL_OK != tws_ParseMultipartEntry(interp, bs, be, multipart_form_data_fields_ptr, multipart_form_data_files_ptr)) {
            Tcl_DecrRefCount(multipart_form_data_fields_ptr);
            Tcl_DecrRefCount(multipart_form_data_files_ptr);
            return TCL_ERROR;
        }

        // setup for next iteration
        bs = next_bs;
        bs += boundary_length + 2;

        // skip "\r\n" or "\n"
        if (bs + 1 < end && *bs == '\r' && *(bs + 1) == '\n') {
            bs += 2;
        } else if (bs < end && *bs == '\r') {
            bs++;
        } else if (bs < end && *bs == '\n') {
            bs++;
        }
    }

    Tcl_Obj *multipart_form_data_fields_key_ptr = Tcl_NewStringObj("fields", -1);
    Tcl_IncrRefCount(multipart_form_data_fields_key_ptr);
    if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, multipart_form_data_fields_key_ptr, multipart_form_data_fields_ptr)) {
        Tcl_DecrRefCount(multipart_form_data_fields_ptr);
        Tcl_DecrRefCount(multipart_form_data_files_ptr);
        Tcl_DecrRefCount(multipart_form_data_fields_key_ptr);
        SetResult("tws_ParseMultipartFormData: multipart/form-data dict write error");
        return TCL_ERROR;
    }

    Tcl_Obj *multipart_form_data_files_key_ptr = Tcl_NewStringObj("files", -1);
    Tcl_IncrRefCount(multipart_form_data_files_key_ptr);
    if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, multipart_form_data_files_key_ptr, multipart_form_data_files_ptr)) {
        Tcl_DecrRefCount(multipart_form_data_fields_ptr);
        Tcl_DecrRefCount(multipart_form_data_files_ptr);
        Tcl_DecrRefCount(multipart_form_data_fields_key_ptr);
        Tcl_DecrRefCount(multipart_form_data_files_key_ptr);
        SetResult("tws_ParseMultipartFormData: multipart/form-data dict write error");
        return TCL_ERROR;
    }

    Tcl_DecrRefCount(multipart_form_data_fields_ptr);
    Tcl_DecrRefCount(multipart_form_data_files_ptr);
    Tcl_DecrRefCount(multipart_form_data_fields_key_ptr);
    Tcl_DecrRefCount(multipart_form_data_files_key_ptr);
    return TCL_OK;
}

static int tws_AddUrlEncodedFormField(Tcl_Interp *interp, Tcl_Obj *fields_ptr, Tcl_Obj *multivalue_fields_ptr, const char *key, const char *value, int value_length) {
    Tcl_Encoding encoding = Tcl_GetEncoding(interp, "utf-8");

    Tcl_Obj *keyPtr = Tcl_NewStringObj(key, value - key - 1);
    Tcl_Obj *valuePtr = Tcl_NewStringObj("", 0);
    if (TCL_OK != tws_UrlDecode(interp, encoding, value, value_length, valuePtr)) {
        SetResult("AddUrlEncodedFormField: urldecode error");
        return TCL_ERROR;
    }
    if (TCL_OK != Tcl_DictObjPut(interp, fields_ptr, keyPtr, valuePtr)) {
        SetResult("AddUrlEncodedFormField: dict write error");
        return TCL_ERROR;
    }
}

static int tws_ParseUrlEncodedForm(Tcl_Interp *interp, Tcl_Obj *body_ptr, Tcl_Obj *result_ptr) {
    int body_length;
    const char *body = Tcl_GetStringFromObj(body_ptr, &body_length);

    Tcl_Obj *fields_ptr = Tcl_NewDictObj();
    Tcl_IncrRefCount(fields_ptr);
    Tcl_Obj *multivalue_fields_ptr = Tcl_NewDictObj();
    Tcl_IncrRefCount(multivalue_fields_ptr);

    const char *p = body;
    const char *end = body + body_length;

    while (p < end) {
        const char *key = p;
        const char *value = NULL;
        while (p < end && *p != '=') {
            p++;
        }
        if (p == end) {
            Tcl_DecrRefCount(fields_ptr);
            Tcl_DecrRefCount(multivalue_fields_ptr);
            SetResult("ParseUrlEncodedForm: malformed urlencoded form data");
            return TCL_ERROR;
        }
        value = p + 1;
        while (p < end && *p != '&') {
            p++;
        }
        if (p == end) {
            if (TCL_OK != tws_AddUrlEncodedFormField(interp, fields_ptr, multivalue_fields_ptr, key, value, p - value)) {
                Tcl_DecrRefCount(fields_ptr);
                Tcl_DecrRefCount(multivalue_fields_ptr);
                SetResult("ParseUrlEncodedForm: dict write error");
                return TCL_ERROR;
            }
            break;
        }
        if (TCL_OK != tws_AddUrlEncodedFormField(interp, fields_ptr, multivalue_fields_ptr, key, value, p - value)) {
            Tcl_DecrRefCount(fields_ptr);
            Tcl_DecrRefCount(multivalue_fields_ptr);
            SetResult("ParseUrlEncodedForm: dict write error");
            return TCL_ERROR;
        }
        p++;
    }

    if (TCL_OK != Tcl_DictObjPut(interp, result_ptr, Tcl_NewStringObj("fields", -1), fields_ptr)) {
        Tcl_DecrRefCount(fields_ptr);
        Tcl_DecrRefCount(multivalue_fields_ptr);
        SetResult("ParseUrlEncodedForm: urlencoded form data dict write error");
        return TCL_ERROR;
    }

    if (TCL_OK != Tcl_DictObjPut(interp, result_ptr, Tcl_NewStringObj("multivalueFields", -1), multivalue_fields_ptr)) {
        Tcl_DecrRefCount(fields_ptr);
        Tcl_DecrRefCount(multivalue_fields_ptr);
        SetResult("ParseUrlEncodedForm: urlencoded form data dict write error");
        return TCL_ERROR;
    }

    Tcl_DecrRefCount(fields_ptr);
    Tcl_DecrRefCount(multivalue_fields_ptr);
    return TCL_OK;
}

int tws_GetFormCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "GetFormCmd\n"));
    CheckArgs(2, 2, 1, "request_dict");

//    fprintf(stderr, "req=%s\n", Tcl_GetString(objv[1]));

    Tcl_Obj *body_ptr = NULL;
    Tcl_Obj *body_key_ptr = Tcl_NewStringObj("body", -1);
    Tcl_IncrRefCount(body_key_ptr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[1], body_key_ptr, &body_ptr)) {
        Tcl_DecrRefCount(body_key_ptr);
        SetResult("get_form: error reading body from request dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(body_key_ptr);

    if (!body_ptr) {
        SetResult("get_form: no body in request dict");
        return TCL_ERROR;
    }

    Tcl_Obj *multipart_boundary_ptr = NULL;
    Tcl_Obj *multipart_boundary_key_ptr = Tcl_NewStringObj("multipartBoundary", -1);
    Tcl_IncrRefCount(multipart_boundary_key_ptr);
    if (TCL_OK != Tcl_DictObjGet(interp, objv[1], multipart_boundary_key_ptr, &multipart_boundary_ptr)) {
        Tcl_DecrRefCount(multipart_boundary_key_ptr);
        SetResult("get_form: error reading multipart_boundary from request dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(multipart_boundary_key_ptr);

    Tcl_Obj *result_ptr = Tcl_NewDictObj();
    Tcl_IncrRefCount(result_ptr);
    if (multipart_boundary_ptr) {
        DBG(fprintf(stderr, "multipart form data with boundary=%s\n", Tcl_GetString(multipart_boundary_ptr)));

        int body_b64_length;
        const char *body_b64 = Tcl_GetStringFromObj(body_ptr, &body_b64_length);

        char *body = Tcl_Alloc(3 * body_b64_length / 4 + 2);
        size_t body_length;
        if (base64_decode(body_b64, body_b64_length, body, &body_length)) {
            Tcl_DecrRefCount(result_ptr);
            Tcl_Free(body);
            SetResult("base64_decode failed");
            return TCL_ERROR;
        }

        if (TCL_OK != tws_ParseMultipartFormData(interp, body, body_length, multipart_boundary_ptr, result_ptr)) {
            Tcl_DecrRefCount(result_ptr);
            SetResult("get_form: error parsing multipart form data");
            return TCL_ERROR;
        }
    } else {
        // check if "content-type" is "application/x-form-urlencoded"
        Tcl_Obj *content_type_ptr = NULL;
        Tcl_Obj *content_type_key_ptr = Tcl_NewStringObj("content-type", -1);
        Tcl_IncrRefCount(content_type_key_ptr);
        if (TCL_OK != Tcl_DictObjGet(interp, objv[1], content_type_key_ptr, &content_type_ptr)) {
            Tcl_DecrRefCount(content_type_key_ptr);
            Tcl_DecrRefCount(result_ptr);
            SetResult("get_form: error reading content-type from request dict");
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(content_type_key_ptr);

        if (content_type_ptr) {
            int content_type_len;
            const char *content_type = Tcl_GetStringFromObj(content_type_ptr, &content_type_len);
            if (content_type_len >= 33 && strncmp(content_type, "application/x-www-form-urlencoded", 33) == 0) {
                // parse urlencoded form data
                if (TCL_OK != tws_ParseUrlEncodedForm(interp, body_ptr, result_ptr)) {
                    Tcl_DecrRefCount(result_ptr);
                    SetResult("get_form: error parsing urlencoded form data");
                    return TCL_ERROR;
                }
            }
        }
    }

    Tcl_SetObjResult(interp, result_ptr);
    Tcl_DecrRefCount(result_ptr);
    return TCL_OK;
}
