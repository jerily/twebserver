/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include "request.h"
#include "uri.h"
#include "base64.h"

// search a string for any of a set of bytes
const char *tws_strpbrk(const char *s, const char *end, const char *accept) {
    while (s < end && *s != '\0') {
        const char *p = accept;
        while (*p != '\0') {
            if (*s == *p) {
                return s;
            }
            p++;
        }
        s++;
    }
    return NULL;
}

int tws_UrlDecode(Tcl_Interp *interp, Tcl_Encoding encoding, const char *value, int value_length, Tcl_Obj *resultPtr) {
    // check if url decoding is needed, value is not '\0' terminated
    const char *p = value;
    const char *end = value + value_length;
    p = tws_strpbrk(value, end, "%+");

    // no url decoding is needed
    if (p == NULL) {
        Tcl_SetStringObj(resultPtr, value, value_length);
        return TCL_OK;
    }

    // url decoding is needed
    // decode "value" into "valuePtr"

    // allocate memory for "valuePtr"
    char *valuePtr = (char *) Tcl_Alloc(value_length + 1);
    char *q = valuePtr;
    while (p != NULL) {
        // copy the part of "value" before the first "%"
        memcpy(q, value, p - value);
        q += p - value;
        value = p;
        if (*value == '%') {
            // decode "%xx" into a single char
            value++;
            if (value + 2 > end) {
                Tcl_Free(valuePtr);
                SetResult("urldecode error: invalid %xx sequence");
                return TCL_ERROR;
            }
            if (!tws_IsCharOfType(value[0], CHAR_HEX) || !tws_IsCharOfType(value[1], CHAR_HEX)) {
                Tcl_Free(valuePtr);
                SetResult("urldecode error: invalid %xx sequence");
                return TCL_ERROR;
            }
            unsigned char c = (tws_HexCharToValue(value[0]) << 4) + tws_HexCharToValue(value[1]);
            *q = (char) c;
            q++;
            value += 2;
        } else if (*value == '+') {
            // decode "+" into a space
            *q = ' ';
            q++;
            value++;
        }
        p = tws_strpbrk(value, end, "%+");
    }
    // copy the rest of "value" into "valuePtr"
    memcpy(q, value, end - value);
    q += end - value;

    int dstLen = 2 * (q - valuePtr) + 1;
    char *dst = (char *) Tcl_Alloc(dstLen);
    int srcRead;
    int dstWrote;
    int dstChars;
    if (TCL_OK != Tcl_ExternalToUtf(
            interp,
            encoding,
            valuePtr,
            q - valuePtr,
            TCL_ENCODING_STOPONERROR,
            NULL,
            dst,
            dstLen,
            &srcRead,
            &dstWrote,
            &dstChars)
            ) {
        Tcl_Free(dst);
        Tcl_Free(valuePtr);
        SetResult("urldecode error: invalid utf-8 sequence");
        return TCL_ERROR;
    }
    Tcl_SetStringObj(resultPtr, dst, dstWrote);
    Tcl_Free(dst);
    Tcl_Free(valuePtr);
    return TCL_OK;
}

int tws_UrlEncode(Tcl_Interp *interp, int enc_flags, const char *value, int value_length, Tcl_Obj **valuePtrPtr) {
    // use "enc" to encode "value" into "valuePtr"
    // allocate memory for "valuePtr"
    char *valuePtr = (char *) Tcl_Alloc(3 * value_length + 1);
    char *q = valuePtr;
    const char *p = value;
    const char *end = value + value_length;
    while (p < end) {
        unsigned char c = *p;
        if (tws_IsCharOfType(c, enc_flags)) {
            *q = c;
            q++;
        } else {
            if (c == ' ' && (enc_flags & CHAR_QUERY)) {
                // encode "c" into "+"
                *q++ = '+';
            } else {
                // encode "c" into "%xx"
                char hex0 = hex_digits[(c >> 4) &
                                       0xF]; // Extract the high nibble of c and use it as an index in the lookup table
                char hex1 = hex_digits[c &
                                       0xF]; // Extract the low nibble of c and use it as an index in the lookup table

                *q++ = '%';
                *q++ = hex0;
                *q++ = hex1;
            }
        }
        p++;
    }
    *valuePtrPtr = Tcl_NewStringObj(valuePtr, q - valuePtr);
    Tcl_Free(valuePtr);
    return TCL_OK;
}

static int tws_AddQueryStringParameter(Tcl_Interp *interp, Tcl_Encoding encoding, Tcl_Obj *query_string_parameters_ptr,
                                       Tcl_Obj *multivalue_query_string_parameters_ptr, const char *key, const char *value,
                                       int value_length) {

    // check if "key" already exists in "queryStringParameters"
    Tcl_Obj *key_ptr = Tcl_NewStringObj(key, value - key - 1);
    Tcl_IncrRefCount(key_ptr);
    Tcl_Obj *value_ptr = Tcl_NewStringObj("", 0);
    Tcl_IncrRefCount(value_ptr);
    if (TCL_OK != tws_UrlDecode(interp, encoding, value, value_length, value_ptr)) {
        Tcl_DecrRefCount(value_ptr);
        Tcl_DecrRefCount(key_ptr);
        SetResult("AddQueryStringParameter: urldecode error");
        return TCL_ERROR;
    }
    Tcl_Obj *existing_value_ptr;
    if (TCL_OK != Tcl_DictObjGet(interp, query_string_parameters_ptr, key_ptr, &existing_value_ptr)) {
        Tcl_DecrRefCount(value_ptr);
        Tcl_DecrRefCount(key_ptr);
        SetResult("AddQueryStringParameter: dict get error");
        return TCL_ERROR;
    }
    if (existing_value_ptr) {
        // check if "key" already exists in "multivalueQueryStringParameters"
        Tcl_Obj *multi_value_ptr;
        if (TCL_OK != Tcl_DictObjGet(interp, multivalue_query_string_parameters_ptr, key_ptr, &multi_value_ptr)) {
            Tcl_DecrRefCount(value_ptr);
            Tcl_DecrRefCount(key_ptr);
            SetResult("AddQueryStringParameter: dict get error");
            return TCL_ERROR;
        }
        int should_decr_ref_count = 0;
        if (!multi_value_ptr) {
            // it does not exist, create a new list and add the existing value from queryStringParameters
            multi_value_ptr = Tcl_NewListObj(0, NULL);
            Tcl_IncrRefCount(multi_value_ptr);
            if (TCL_OK != Tcl_ListObjAppendElement(interp, multi_value_ptr, existing_value_ptr)) {
                Tcl_DecrRefCount(value_ptr);
                Tcl_DecrRefCount(key_ptr);
                Tcl_DecrRefCount(multi_value_ptr);
                SetResult("AddQueryStringParameter: list append error");
                return TCL_ERROR;
            }
            should_decr_ref_count = 1;
        }
        // append the new value to the list
        if (TCL_OK != Tcl_ListObjAppendElement(interp, multi_value_ptr, value_ptr)) {
            Tcl_DecrRefCount(value_ptr);
            Tcl_DecrRefCount(key_ptr);
            if (should_decr_ref_count) {
                Tcl_DecrRefCount(multi_value_ptr);
            }
            SetResult("AddQueryStringParameter: list append error");
            return TCL_ERROR;
        }
        if (TCL_OK != Tcl_DictObjPut(interp, multivalue_query_string_parameters_ptr, key_ptr, multi_value_ptr)) {
            Tcl_DecrRefCount(value_ptr);
            Tcl_DecrRefCount(key_ptr);
            if (should_decr_ref_count) {
                Tcl_DecrRefCount(multi_value_ptr);
            }
            SetResult("AddQueryStringParameter: dict put error");
            return TCL_ERROR;
        }
        if (should_decr_ref_count) {
            Tcl_DecrRefCount(multi_value_ptr);
        }
    }
    if (TCL_OK != Tcl_DictObjPut(interp, query_string_parameters_ptr, key_ptr, value_ptr)) {
        Tcl_DecrRefCount(value_ptr);
        Tcl_DecrRefCount(key_ptr);
        SetResult("AddQueryStringParameter: dict put error");
        return TCL_ERROR;
    }

    Tcl_DecrRefCount(value_ptr);
    Tcl_DecrRefCount(key_ptr);
    return TCL_OK;
}

static int
tws_ParseQueryStringParameters(Tcl_Interp *interp, Tcl_Encoding encoding, Tcl_Obj *queryStringPtr, Tcl_Obj *resultPtr) {
    // parse "query_string" into "queryStringParameters" given that it is of the form "key1=value1&key2=value2&..."
    Tcl_Obj *queryStringParametersPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(queryStringParametersPtr);
    Tcl_Obj *multiValueQueryStringParametersPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(multiValueQueryStringParametersPtr);
    int query_string_length;
    const char *query_string = Tcl_GetStringFromObj(queryStringPtr, &query_string_length);
    const char *p = query_string;
    const char *end = query_string + query_string_length;
    while (p < end) {
        const char *key = p;
        const char *value = NULL;
        while (p < end && *p != '=') {
            p++;
        }
        if (p == end) {
            Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
            Tcl_DecrRefCount(queryStringParametersPtr);
            SetResult("query string parse error");
            return TCL_ERROR;
        }
        value = p + 1;
        while (p < end && *p != '&') {
            p++;
        }
        if (p == end) {
            if (TCL_OK !=
                tws_AddQueryStringParameter(interp, encoding, queryStringParametersPtr,
                                            multiValueQueryStringParametersPtr, key,
                                            value, p - value)) {
                Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
                Tcl_DecrRefCount(queryStringParametersPtr);
                SetResult("query string parse error");
                return TCL_ERROR;
            }
            break;
        }
        if (TCL_OK !=
            tws_AddQueryStringParameter(interp, encoding, queryStringParametersPtr, multiValueQueryStringParametersPtr,
                                        key,
                                        value, p - value)) {
            Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
            Tcl_DecrRefCount(queryStringParametersPtr);
            SetResult("query string parse error");
            return TCL_ERROR;
        }
        p++;
    }

    if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("queryStringParameters", -1), queryStringParametersPtr)) {
        Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
        Tcl_DecrRefCount(queryStringParametersPtr);
        SetResult("query string parameters put error");
        return TCL_ERROR;
    }

    if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("multiValueQueryStringParameters", -1),
                   multiValueQueryStringParametersPtr)) {
        Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
        Tcl_DecrRefCount(queryStringParametersPtr);
        SetResult("multi value query string parameters put error");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
    Tcl_DecrRefCount(queryStringParametersPtr);
    return TCL_OK;
}

static int tws_ParsePathAndQueryString(Tcl_Interp *interp, Tcl_Encoding encoding, const char *url, int url_length,
                                       Tcl_Obj *resultPtr) {
    // parse "path" and "queryStringParameters" from "url"
    const char *p2 = url;
    while (p2 < url + url_length && *p2 != '\0') {
        if (*p2 == '?') {
            int path_length = p2 - url;
            Tcl_Obj *pathPtr = Tcl_NewStringObj("", 0);
            Tcl_IncrRefCount(pathPtr);
            if (TCL_OK != tws_UrlDecode(interp, encoding, url, path_length, pathPtr)) {
                Tcl_DecrRefCount(pathPtr);
                SetResult("path urldecode error");
                return TCL_ERROR;
            }
            if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("path", -1), pathPtr)) {
                Tcl_DecrRefCount(pathPtr);
                SetResult("path dict put error");
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(pathPtr);

            int query_string_length = url + url_length - p2 - 1;
            Tcl_Obj *queryStringPtr = Tcl_NewStringObj(p2 + 1, query_string_length);
            Tcl_IncrRefCount(queryStringPtr);
            if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("queryString", -1), queryStringPtr)) {
                Tcl_DecrRefCount(queryStringPtr);
                SetResult("queryString dict put error");
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(queryStringPtr);
            tws_ParseQueryStringParameters(interp, encoding, queryStringPtr, resultPtr);
            break;
        }
        p2++;
    }
    if (p2 == url + url_length) {
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("path", -1), Tcl_NewStringObj(url, url_length));
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("queryString", -1), Tcl_NewStringObj("", 0));
    }
    return TCL_OK;
}

static inline int tws_IsHttpMethod(const char *p, size_t len) {
    return ((len == 3 &&
             ((*p == 'G' && *(p + 1) == 'E' && *(p + 2) == 'T') || (*p == 'P' && *(p + 1) == 'U' && *(p + 2) == 'T')))
            || (len == 4 &&
                ((*p == 'P' && *(p + 1) == 'O' && *(p + 2) == 'S' && *(p + 3) == 'T') ||
                 (*p == 'H' && *(p + 1) == 'E' && *(p + 2) == 'A' && *(p + 3) == 'D')))
            || (len == 5 &&
                ((*p == 'P' && *(p + 1) == 'A' && *(p + 2) == 'T' && *(p + 3) == 'C' && *(p + 4) == 'H') ||
                 (*p == 'T' && *(p + 1) == 'R' && *(p + 2) == 'A' && *(p + 3) == 'C' && *(p + 4) == 'E')))
            || (len == 6 && *p == 'D' && *(p + 1) == 'E' && *(p + 2) == 'L' && *(p + 3) == 'E' && *(p + 4) == 'T' &&
                *(p + 5) == 'E')
            || (len == 7 && *p == 'O' && *(p + 1) == 'P' && *(p + 2) == 'T' && *(p + 3) == 'I' && *(p + 4) == 'O' &&
                *(p + 5) == 'N' && *(p + 6) == 'S'
            ));
}

static inline int tws_IsHttpVersion(const char *p, size_t len) {
    return (len >= 6 && *p == 'H' && *(p + 1) == 'T' && *(p + 2) == 'T' && *(p + 3) == 'P' && *(p + 4) == '/' &&
            CHARTYPE(digit, *(p + 5)))
           && (len < 7 || *(p + 6) == '.')
           && (len < 8 || CHARTYPE(digit, *(p + 7)));
}

static int tws_ParseRequestLine(Tcl_Interp *interp, Tcl_Encoding encoding, const char **currPtr, const char *end,
                                Tcl_Obj *resultPtr) {
    const char *curr = *currPtr;
    // skip spaces
    while (curr < end && CHARTYPE(space, *curr) != 0) {
        curr++;
    }
    const char *p = curr;

    // collect non-space chars as first token
    while (curr < end && CHARTYPE(space, *curr) == 0) {
        curr++;
    }
    if (curr == end) {
        SetResult("request line parse error: no http method");
        return TCL_ERROR;
    }

    // mark the end of the token and remember as "http_method"
    curr++;
//    char *http_method = strndup(p, curr - p);
//    http_method[curr - p - 1] = '\0';
    int http_method_length = curr - p - 1;

    // check that it is a valid http method:
    // GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE
    if (!tws_IsHttpMethod(p, http_method_length)) {
        SetResult("request line parse error: invalid http method");
        return TCL_ERROR;
    }

    if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("httpMethod", -1), Tcl_NewStringObj(p, http_method_length))) {
        SetResult("request line parse error: dict put error");
        return TCL_ERROR;
    }

    // skip spaces
    while (curr < end && CHARTYPE(space, *curr) != 0) {
        curr++;
    }
    p = curr;

    // collect non-space chars as second token
    while (curr < end && CHARTYPE(space, *curr) == 0) {
        curr++;
    }
    if (curr == end) {
        SetResult("request line parse error: no url");
        return TCL_ERROR;
    }

    // mark the end of the token and remember as "path"
    curr++;
//    char *url = strndup(p, curr - p);
//    url[curr - p - 1] = '\0';
    int url_length = curr - p - 1;

    if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("url", -1), Tcl_NewStringObj(p, url_length))) {
        SetResult("request line parse error: dict put error");
        return TCL_ERROR;
    }

    if (TCL_OK != tws_ParsePathAndQueryString(interp, encoding, p, url_length, resultPtr)) {
        return TCL_ERROR;
    }

    // skip spaces until end of line denoted by "\r\n" or "\n"
    while (curr < end && CHARTYPE(space, *curr) != 0 && *curr != '\r' && *curr != '\n') {
        curr++;
    }
    p = curr;

    if (curr == end) {
        SetResult("request line parse error: no version");
        return TCL_ERROR;
    }

    // parse "version" if we have NOT reached the end of line
    if (*curr != '\r' && *curr != '\n') {

        // collect non-space chars as third token
        while (curr < end && CHARTYPE(space, *curr) == 0) {
            curr++;
        }
        if (curr == end) {
            SetResult("request line parse error: while extracting version");
            return TCL_ERROR;
        }

        if (!tws_IsHttpVersion(p, curr - p)) {
            SetResult("request line parse error: invalid version");
            return TCL_ERROR;
        }

        // mark the end of the token and remember as "version"
        curr++;
        if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("version", -1), Tcl_NewStringObj(p, curr - p - 1))) {
            SetResult("request line parse error: dict put error");
            return TCL_ERROR;
        }
    }

    // skip newline chars
    while (curr < end && (*curr == '\r' || *curr == '\n')) {
        curr++;
    }
    *currPtr = curr;
    return TCL_OK;

}

static int tws_AddHeader(Tcl_Interp *interp, Tcl_Obj *headersPtr, Tcl_Obj *multiValueHeadersPtr, Tcl_Obj *keyPtr,
                         Tcl_Obj *valuePtr) {
    Tcl_Obj *existingValuePtr;
    if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, keyPtr, &existingValuePtr)) {
        SetResult("AddHeader: dict get error");
        return TCL_ERROR;
    }
    if (existingValuePtr) {
        // check if "key" already exists in "multiValueHeaders"
        Tcl_Obj *multiValuePtr;
        if (TCL_OK != Tcl_DictObjGet(interp, multiValueHeadersPtr, keyPtr, &multiValuePtr)) {
            SetResult("AddHeader: dict get error");
            return TCL_ERROR;
        }
        if (!multiValuePtr) {
            // it does not exist, create a new list and add the existing value from headers
            multiValuePtr = Tcl_NewListObj(0, NULL);
            Tcl_IncrRefCount(multiValuePtr);
            if (TCL_OK != Tcl_ListObjAppendElement(interp, multiValuePtr, existingValuePtr)) {
                Tcl_DecrRefCount(multiValuePtr);
                SetResult("AddHeader: list append error");
                return TCL_ERROR;
            }
        } else {
            Tcl_IncrRefCount(multiValuePtr);
        }
        // append the new value to the list
        if (TCL_OK != Tcl_ListObjAppendElement(interp, multiValuePtr, valuePtr)) {
            Tcl_DecrRefCount(multiValuePtr);
            SetResult("AddHeader: list append error");
            return TCL_ERROR;
        }
        if (TCL_OK != Tcl_DictObjPut(interp, multiValueHeadersPtr, keyPtr, multiValuePtr)) {
            Tcl_DecrRefCount(multiValuePtr);
            SetResult("AddHeader: dict put error");
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(multiValuePtr);
    }

    if (TCL_OK != Tcl_DictObjPut(interp, headersPtr, keyPtr, valuePtr)) {
        SetResult("AddHeader: dict put error");
        return TCL_ERROR;
    }
    return TCL_OK;
}

static int tws_ParseHeaders(Tcl_Interp *interp, const char **currPtr, const char *end, Tcl_Obj *headersPtr,
                            Tcl_Obj *multiValueHeadersPtr) {
    // parse the headers, each header is a line of the form "key: value"
    // stop when we reach an empty line denoted by "\r\n" or "\n"
    const char *curr = *currPtr;
    while (curr < end) {
        const char *p = curr;

        // collect non-space chars as header key
        while (curr < end && CHARTYPE(space, *curr) == 0 && *curr != ':') {
            curr++;
        }
        if (curr == end) {
            SetResult("ParseHeaders: no header key");
            return TCL_ERROR;
        }

        // mark the end of the token and remember as "key"
        curr++;
        size_t keylen = curr - p - 1;
        char *key = tws_strndup(p, keylen);
        // lowercase "key"
        for (int i = 0; i < keylen; i++) {
            key[i] = tolower(key[i]);
        }
        Tcl_Obj *keyPtr = Tcl_NewStringObj(key, keylen);
        Tcl_IncrRefCount(keyPtr);
        Tcl_Free(key);

        // skip spaces
        while (curr < end && CHARTYPE(space, *curr) != 0) {
            curr++;
        }
        p = curr;

        // collect all chars to the end of line as header value
        while (curr < end && *curr != '\r' && *curr != '\n') {
            curr++;
        }

        // mark the end of the token and remember as "value"
//        curr++;

        size_t valuelen = curr - p;
        char *value = tws_strndup(p, valuelen);
        Tcl_Obj *valuePtr = Tcl_NewStringObj(value, valuelen);
        Tcl_IncrRefCount(valuePtr);
        Tcl_Free(value);

        DBG(fprintf(stderr, "key=%s value=%s\n", Tcl_GetString(keyPtr), Tcl_GetString(valuePtr)));

        // skip spaces until end of line denoted by "\r\n" or "\n"
        while (curr < end && CHARTYPE(space, *curr) != 0 && *curr != '\r' && *curr != '\n') {
            curr++;
        }

        // check if we reached the end
        if (curr == end) {
            if (TCL_OK != tws_AddHeader(interp, headersPtr, multiValueHeadersPtr, keyPtr, valuePtr)) {
                Tcl_DecrRefCount(keyPtr);
                Tcl_DecrRefCount(valuePtr);
                SetResult("ParseHeaders: failed adding header (1)");
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(keyPtr);
            Tcl_DecrRefCount(valuePtr);
            break;
        }

        // print 3 chars from curr
//        fprintf(stderr, "here1: curr[0]=%c curr[1]=%c curr[2]=%c\n", curr[0], curr[1], curr[2]);

        // skip "\r\n" or "\n" at most once
        if (curr + 1 < end && *curr == '\r' && *(curr + 1) == '\n') {
            curr += 2;
        } else if (curr < end && *curr == '\r') {
            curr++;
        } else if (curr < end && *curr == '\n') {
            curr++;
        }

        // check if we reached the end
        if (curr == end) {
            if (TCL_OK != tws_AddHeader(interp, headersPtr, multiValueHeadersPtr, keyPtr, valuePtr)) {
                Tcl_DecrRefCount(keyPtr);
                Tcl_DecrRefCount(valuePtr);
                SetResult("ParseHeaders: failed adding header (2)");
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(keyPtr);
            Tcl_DecrRefCount(valuePtr);
            break;
        }

        // check if the line starts with a space, if so, it is a continuation of the previous header
        while (curr < end && *curr == ' ') {
            DBG(fprintf(stderr, "continuation curr=%p end=%p intchar=%d\n", curr, end, (int) curr[0]));
            // skip spaces
            while (curr < end && CHARTYPE(space, *curr) != 0) {
                curr++;
            }
            p = curr;

            // read the new line to the end by advancing "curr"
            while (curr < end && *curr != '\r' && *curr != '\n') {
                curr++;
            }

            // mark the end of the string and remember as "continuation_value"
            curr++;
            size_t continuation_valuelen = curr - p - 1;
            char *continuation_value = tws_strndup(p, continuation_valuelen);
            Tcl_Obj *continuation_valuePtr = Tcl_NewStringObj(continuation_value, continuation_valuelen);
            Tcl_IncrRefCount(continuation_valuePtr);
            // append the continuation value to the previous value
            Tcl_AppendObjToObj(valuePtr, continuation_valuePtr);
            Tcl_DecrRefCount(continuation_valuePtr);
            Tcl_Free(continuation_value);

            // skip "\r\n" or "\n" at most once
            if (curr + 1 < end && *curr == '\r' && *(curr + 1) == '\n') {
                curr += 2;
            } else if (curr < end && *curr == '\r') {
                curr++;
            } else if (curr < end && *curr == '\n') {
                curr++;
            }

        }

        if (TCL_OK != tws_AddHeader(interp, headersPtr, multiValueHeadersPtr, keyPtr, valuePtr)) {
            Tcl_DecrRefCount(keyPtr);
            Tcl_DecrRefCount(valuePtr);
            SetResult("ParseHeaders: failed adding header (3)");
            return TCL_ERROR;
        }
        Tcl_DecrRefCount(keyPtr);
        Tcl_DecrRefCount(valuePtr);

        // print 3 chars from curr
//        fprintf(stderr, "here2: curr[0]=%c curr[1]=%c curr[2]=%c\n", curr[0], curr[1], curr[2]);

        // check if we reached a blank line
        if (curr + 1 < end && *curr == '\r' && *(curr + 1) == '\n') {
            curr += 2;
            break;
        } else if (curr < end && *curr == '\r') {
            curr++;
            break;
        } else if (curr < end && *curr == '\n') {
            curr++;
            break;
        }
    }
    *currPtr = curr;
    return TCL_OK;

}

int tws_ParseBody(Tcl_Interp *interp, const char *curr, const char *end, Tcl_Obj *headersPtr, Tcl_Obj *resultPtr) {

    Tcl_Obj *content_type_ptr;
    Tcl_Obj *content_type_key_ptr = Tcl_NewStringObj("content-type", -1);
    Tcl_IncrRefCount(content_type_key_ptr);
    if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, content_type_key_ptr, &content_type_ptr)) {
        Tcl_DecrRefCount(content_type_key_ptr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(content_type_key_ptr);

    int content_length = end - curr;


    int base64_encode_it = 0;
    if (content_type_ptr) {
        int content_type_length;
        const char *content_type = Tcl_GetStringFromObj(content_type_ptr, &content_type_length);
        base64_encode_it = tws_IsBinaryType(content_type, content_type_length);
        // check if binary mime type: application/* (except application/json and application/xml), image/*, audio/*, video/*
        if (base64_encode_it && content_type_length >= 19 && content_type[0] == 'm' && content_type[9] == '/' && content_type[10] == 'f' && strncmp(content_type, "multipart/form-data", 19) == 0) {
            // multipart/form-data
            base64_encode_it = 1;
            // find semicolon
            const char *p = content_type + 19;
            const char *content_type_end = content_type + content_type_length;
            while (p < content_type_end && *p != ';') {
                p++;
            }
            // skip semicolon
            p++;
            // skip spaces
            while (p < content_type_end && CHARTYPE(space, *p) != 0) {
                p++;
            }
            // check character by character if we have "boundary="
            if (p + 9 < content_type_end && *p == 'b' && *(p + 1) == 'o' && *(p + 2) == 'u' && *(p + 3) == 'n' && *(p + 4) == 'd' && *(p + 5) == 'a' && *(p + 6) == 'r' && *(p + 7) == 'y' && *(p + 8) == '=') {
                // skip "boundary="
                p += 9;
                // check if we have a boundary
                if (p < content_type_end) {
                    // remember the boundary
                    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("multipartBoundary", -1), Tcl_NewStringObj(p, content_type_end - p));
                }
            }
        }
    }
    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("isBase64Encoded", -1), Tcl_NewBooleanObj(base64_encode_it));

    if (base64_encode_it) {
        // base64 encode the body and remember as "body"
        char *body = Tcl_Alloc(content_length * 2);
        size_t bodyLength;
        if (base64_encode(curr, content_length, body, &bodyLength)) {
            Tcl_Free(body);
            SetResult("base64_encode failed");
            return TCL_ERROR;
        }
        Tcl_Obj *bodyPtr = Tcl_NewStringObj(body, bodyLength);
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("body", -1), bodyPtr);
        Tcl_Free(body);
    } else {
        // mark the end of the token and remember as "body"
        char *body = tws_strndup(curr, content_length);
        Tcl_Obj *bodyPtr = Tcl_NewStringObj(body, content_length);
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("body", -1), bodyPtr);
        Tcl_Free(body);
    }

    return TCL_OK;
}

int tws_ParseRequest(Tcl_Interp *interp, Tcl_Encoding encoding, Tcl_DString *dsPtr, Tcl_Obj *dictPtr, int *offset) {

//    String version;
//    String path;
//    String httpMethod;
//    Map<String, String> headers;
//    Map<String, List<String>> multiValueHeaders;
//    Map<String, String> queryStringParameters;
//    Map<String, List<String>> multiValueQueryStringParameters;
//    Map<String, String> pathParameters;
//    String body;
//    Boolean isBase64Encoded;

    const char *request = Tcl_DStringValue(dsPtr);
    int length = Tcl_DStringLength(dsPtr);

    const char *curr = request;
    const char *end = request + length;

    // parse the first line of the request
    if (TCL_OK != tws_ParseRequestLine(interp, encoding, &curr, end, dictPtr)) {
        return TCL_ERROR;
    }
    DBG(fprintf(stderr, "req dict after parse request line: %s\n", Tcl_GetString(dictPtr)));

    Tcl_Obj *headersPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(headersPtr);
    Tcl_Obj *multiValueHeadersPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(multiValueHeadersPtr);

    if (TCL_OK != tws_ParseHeaders(interp, &curr, end, headersPtr, multiValueHeadersPtr)) {
        Tcl_DecrRefCount(multiValueHeadersPtr);
        Tcl_DecrRefCount(headersPtr);
        return TCL_ERROR;
    }

    if (TCL_OK != Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("headers", -1), headersPtr)) {
        Tcl_DecrRefCount(multiValueHeadersPtr);
        Tcl_DecrRefCount(headersPtr);
        return TCL_ERROR;
    }

    if (TCL_OK != Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("multiValueHeaders", -1), multiValueHeadersPtr)) {
        Tcl_DecrRefCount(multiValueHeadersPtr);
        Tcl_DecrRefCount(headersPtr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(multiValueHeadersPtr);
    Tcl_DecrRefCount(headersPtr);

//    tws_ParseBody(interp, curr, end, dictPtr, contentLengthPtr, contentTypePtr);

    *offset = curr - request;
    return TCL_OK;
}

// gzip is enabled q-values greater than 0.001
static int tws_GzipAcceptEncoding(const char *accept_encoding, int accept_encoding_length) {
    // check if "accept_encoding" contains "gzip"
    const char *p = accept_encoding;
    const char *end = accept_encoding + accept_encoding_length;

    // use strstr to find the first "gzip" in "accept_encoding"
    p = strstr(p, "gzip");

    if (!p) {
        return 0;
    }

    p = p + 4;

    while (p < end) {
        switch (*p++) {
            case ',':
                return 1;
            case ';':
                goto quantity;
            case ' ':
                continue;
            default:
                return 0;
        }
    }

    return 1;

    quantity:
    while (p < end) {
        switch (*p++) {
            case 'q':
            case 'Q':
                goto equal;
            case ' ':
                continue;
            default:
                return 0;
        }
    }
    return 1;

    equal:
    if (p + 2 > end || *p++ != '=') {
        return 0;
    }

    double qvalue = strtod(p, NULL);
    return qvalue >= 0.001 && qvalue <= 1.0;
}

int tws_ParseConnectionKeepalive(Tcl_Interp *interp, Tcl_Obj *headersPtr, int *keepalive) {
    Tcl_Obj *connectionPtr;
    Tcl_Obj *connectionKeyPtr = Tcl_NewStringObj("connection", -1);
    Tcl_IncrRefCount(connectionKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, connectionKeyPtr, &connectionPtr)) {
        Tcl_DecrRefCount(connectionKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(connectionKeyPtr);
    if (!connectionPtr) {
        return TCL_OK;
    }

    int connection_length;
    const char *connection = Tcl_GetStringFromObj(connectionPtr, &connection_length);
    if (connection_length == 10 && strncmp(connection, "keep-alive", 10) == 0) {
        *keepalive = 1;
    }
    return TCL_OK;
}

int tws_ParseAcceptEncoding(Tcl_Interp *interp, Tcl_Obj *headersPtr, tws_compression_method_t *compression) {
    // parse "Accept-Encoding" header and set "compression" accordingly

    Tcl_Obj *acceptEncodingPtr;
    Tcl_Obj *acceptEncodingKeyPtr = Tcl_NewStringObj("accept-encoding", -1);
    Tcl_IncrRefCount(acceptEncodingKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, acceptEncodingKeyPtr, &acceptEncodingPtr)) {
        Tcl_DecrRefCount(acceptEncodingKeyPtr);
        SetResult("error reading dict");
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(acceptEncodingKeyPtr);
    if (!acceptEncodingPtr) {
        *compression = NO_COMPRESSION;
        return TCL_OK;
    }

    int accept_encoding_length;
    const char *accept_encoding = Tcl_GetStringFromObj(acceptEncodingPtr, &accept_encoding_length);

    /*
     * test first for the most common case "gzip,...":
     *   MSIE:    "gzip, deflate"
     *   Firefox: "gzip,deflate"
     *   Chrome:  "gzip,deflate,sdch"
     *   Safari:  "gzip, deflate"
     *   Opera:   "gzip, deflate"
     */

    if (accept_encoding_length >= 5 && strncmp(accept_encoding, "gzip,", 5) == 0) {
        *compression = GZIP_COMPRESSION;
        return TCL_OK;
    }

    if (tws_GzipAcceptEncoding(accept_encoding, accept_encoding_length)) {
        *compression = GZIP_COMPRESSION;
        return TCL_OK;
    }

    *compression = NO_COMPRESSION;
    return TCL_OK;
}
