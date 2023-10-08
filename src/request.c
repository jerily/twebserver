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

static int tws_AddQueryStringParameter(Tcl_Interp *interp, Tcl_Encoding encoding, Tcl_Obj *queryStringParametersPtr,
                                       Tcl_Obj *multivalueQueryStringParametersPtr, const char *key, const char *value,
                                       int value_length) {
    // check if "key" already exists in "queryStringParameters"
    Tcl_Obj *keyPtr = Tcl_NewStringObj(key, value - key - 1);
    Tcl_Obj *valuePtr = Tcl_NewStringObj("", 0);
    if (TCL_OK != tws_UrlDecode(interp, encoding, value, value_length, valuePtr)) {
        SetResult("query string urldecode error");
        return TCL_ERROR;
    }
    Tcl_Obj *existingValuePtr;
    Tcl_DictObjGet(interp, queryStringParametersPtr, keyPtr, &existingValuePtr);
    if (existingValuePtr) {
        // check if "key" already exists in "multivalueQueryStringParameters"
        Tcl_Obj *multiValuePtr;
        Tcl_DictObjGet(interp, multivalueQueryStringParametersPtr, keyPtr, &multiValuePtr);
        if (!multiValuePtr) {
            // it does not exist, create a new list and add the existing value from queryStringParameters
            multiValuePtr = Tcl_NewListObj(0, NULL);
            Tcl_ListObjAppendElement(interp, multiValuePtr, existingValuePtr);
        }
        // append the new value to the list
        Tcl_ListObjAppendElement(interp, multiValuePtr, valuePtr);
        Tcl_DictObjPut(interp, multivalueQueryStringParametersPtr, keyPtr, multiValuePtr);
    }
    Tcl_DictObjPut(interp, queryStringParametersPtr, keyPtr, valuePtr);
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
    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("queryStringParameters", -1), queryStringParametersPtr);
    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("multiValueQueryStringParameters", -1),
                   multiValueQueryStringParametersPtr);
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
            if (TCL_OK != tws_UrlDecode(interp, encoding, url, path_length, pathPtr)) {
                SetResult("path urldecode error");
                return TCL_ERROR;
            }
            Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("path", -1), pathPtr);
            int query_string_length = url + url_length - p2 - 1;
            Tcl_Obj *queryStringPtr = Tcl_NewStringObj(p2 + 1, query_string_length);
            Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("queryString", -1), queryStringPtr);
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

    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("httpMethod", -1), Tcl_NewStringObj(p, http_method_length));

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

    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("url", -1), Tcl_NewStringObj(p, url_length));

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

        // mark the end of the token and remember as "version"
        curr++;
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("version", -1), Tcl_NewStringObj(p, curr - p - 1));
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
    Tcl_DictObjGet(interp, headersPtr, keyPtr, &existingValuePtr);
    if (existingValuePtr) {
        // check if "key" already exists in "multiValueHeaders"
        Tcl_Obj *multiValuePtr;
        Tcl_DictObjGet(interp, multiValueHeadersPtr, keyPtr, &multiValuePtr);
        if (!multiValuePtr) {
            // it does not exist, create a new list and add the existing value from headers
            multiValuePtr = Tcl_NewListObj(0, NULL);
            Tcl_ListObjAppendElement(interp, multiValuePtr, existingValuePtr);
        }
        // append the new value to the list
        Tcl_ListObjAppendElement(interp, multiValuePtr, valuePtr);
        Tcl_DictObjPut(interp, multiValueHeadersPtr, keyPtr, multiValuePtr);
    }
    Tcl_DictObjPut(interp, headersPtr, keyPtr, valuePtr);
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
            goto done;
        }

        // mark the end of the token and remember as "key"
        curr++;
        int keylen = curr - p - 1;
        char *key = strndup(p, curr - p);
        // lowercase "key"
        for (int i = 0; i < keylen; i++) {
            key[i] = tolower(key[i]);
        }
        key[curr - p - 1] = '\0';
        Tcl_Obj *keyPtr = Tcl_NewStringObj(key, keylen);
        free(key);

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
        curr++;
        int valuelen = curr - p - 1;
        char *value = strndup(p, curr - p);
        value[curr - p - 1] = '\0';
        Tcl_Obj *valuePtr = Tcl_NewStringObj(value, valuelen);
        free(value);

//        DBG(fprintf(stderr, "key=%s value=%s\n", key, value));

        // skip spaces until end of line denoted by "\r\n" or "\n"
        while (curr < end && CHARTYPE(space, *curr) != 0 && *curr != '\r' && *curr != '\n') {
            curr++;
        }

        // check if we reached the end
        if (curr == end) {
            if (TCL_OK != tws_AddHeader(interp, headersPtr, multiValueHeadersPtr, keyPtr, valuePtr)) {
                goto done;
            }
            break;
        }

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
                goto done;
            }
            break;
        }

        // check if the line starts with a space, if so, it is a continuation of the previous header
        while (curr < end && *curr == ' ') {
            fprintf(stderr, "continuation curr=%p end=%p intchar=%d\n", curr, end, (int) curr[0]);
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
            int continuation_valuelen = curr - p;
            char *continuation_value = strndup(p, curr - p);
            continuation_value[curr - p - 1] = '\0';
            Tcl_Obj *continuation_valuePtr = Tcl_NewStringObj(continuation_value, continuation_valuelen);

            // append the continuation value to the previous value
            Tcl_AppendObjToObj(valuePtr, continuation_valuePtr);
            free(continuation_value);

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
            goto done;
        }

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

    done:
    SetResult("headers parse error");
    return TCL_ERROR;
}

static int
tws_ParseBody(Tcl_Interp *interp, const char *curr, const char *end, Tcl_Obj *resultPtr, Tcl_Obj *contentLengthPtr,
              Tcl_Obj *contentTypePtr) {
    int contentLength;
    if (contentLengthPtr) {
        if (Tcl_GetIntFromObj(interp, contentLengthPtr, &contentLength) != TCL_OK) {
            SetResult("Content-Length must be an integer");
            return TCL_ERROR;
        }

        // check if we have enough bytes in the body
        if (end - curr < contentLength) {
            contentLength = end - curr;
        }
    } else {
        if (curr == end) {
            Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("isBase64Encoded", -1), Tcl_NewBooleanObj(0));
            Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("body", -1), Tcl_NewStringObj("", 0));
            return TCL_OK;
        }

        contentLength = end - curr;
    }

    DBG(fprintf(stderr, "contentLength=%d\n", contentLength));

    int base64_encode_it = 0;
    if (contentTypePtr) {
        int contentTypeLength;
        const char *content_type = Tcl_GetStringFromObj(contentTypePtr, &contentTypeLength);
        // check if binary mime type: image/* and application/octet
        if (contentTypeLength >= 16 && strncmp(content_type, "application/octet", 16) == 0) {
            base64_encode_it = 1;
        } else if (contentTypeLength >= 6 && strncmp(content_type, "image/", 6) == 0) {
            base64_encode_it = 1;
        }
    }
    Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("isBase64Encoded", -1), Tcl_NewBooleanObj(base64_encode_it));

    if (base64_encode_it) {
        // base64 encode the body and remember as "body"
        char *body = Tcl_Alloc(contentLength * 2);
        size_t bodyLength;
        if (base64_encode(curr, contentLength, body, &bodyLength)) {
            Tcl_Free(body);
            SetResult("base64_encode failed");
            return TCL_ERROR;
        }
        Tcl_Obj *bodyPtr = Tcl_NewStringObj(body, bodyLength);
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("body", -1), bodyPtr);
        Tcl_Free(body);
    } else {
        // mark the end of the token and remember as "body"
        char *body = strndup(curr, contentLength + 1);
        body[contentLength] = '\0';
        Tcl_Obj *bodyPtr = Tcl_NewStringObj(body, contentLength);
        Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("body", -1), bodyPtr);
        free(body);
    }

    return TCL_OK;
}

int tws_ParseRequest(Tcl_Interp *interp, Tcl_Encoding encoding, Tcl_DString *dsPtr, Tcl_Obj *dictPtr) {

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

    Tcl_Obj *headersPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(headersPtr);
    Tcl_Obj *multiValueHeadersPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(multiValueHeadersPtr);
    if (TCL_OK != tws_ParseHeaders(interp, &curr, end, headersPtr, multiValueHeadersPtr)) {
        Tcl_DecrRefCount(multiValueHeadersPtr);
        Tcl_DecrRefCount(headersPtr);
        return TCL_ERROR;
    }
    Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("headers", -1), headersPtr);
    Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("multiValueHeaders", -1), multiValueHeadersPtr);

    // get "Content-Length" header
    Tcl_Obj *contentLengthPtr;
    Tcl_Obj *contentLengthKeyPtr = Tcl_NewStringObj("content-length", -1);
    Tcl_IncrRefCount(contentLengthKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, contentLengthKeyPtr, &contentLengthPtr)) {
        Tcl_DecrRefCount(multiValueHeadersPtr);
        Tcl_DecrRefCount(headersPtr);
        Tcl_DecrRefCount(contentLengthKeyPtr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(contentLengthKeyPtr);

    Tcl_Obj *contentTypePtr;
    Tcl_Obj *contentTypeKeyPtr = Tcl_NewStringObj("content-type", -1);
    Tcl_IncrRefCount(contentTypeKeyPtr);
    if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, contentTypeKeyPtr, &contentTypePtr)) {
        Tcl_DecrRefCount(multiValueHeadersPtr);
        Tcl_DecrRefCount(headersPtr);
        Tcl_DecrRefCount(contentTypeKeyPtr);
        return TCL_ERROR;
    }
    Tcl_DecrRefCount(contentTypeKeyPtr);

    Tcl_DecrRefCount(multiValueHeadersPtr);
    Tcl_DecrRefCount(headersPtr);

    tws_ParseBody(interp, curr, end, dictPtr, contentLengthPtr, contentTypePtr);

    return TCL_OK;
}

int tws_ParseRequestCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "ParseRequestCmd\n"));
    CheckArgs(2, 3, 1, "request ?encoding_name?");

    int length;
    const char *request = Tcl_GetStringFromObj(objv[1], &length);

    Tcl_Encoding encoding;
    if (objc == 3) {
        encoding = Tcl_GetEncoding(interp, Tcl_GetString(objv[2]));
    } else {
        encoding = Tcl_GetEncoding(interp, "utf-8");
    }

    DBG(fprintf(stderr, "request=%s\n", request));

    Tcl_DString ds;
    Tcl_DStringInit(&ds);
    Tcl_DStringAppend(&ds, request, length);
    Tcl_Obj *resultPtr = Tcl_NewDictObj();
    Tcl_IncrRefCount(resultPtr);
    if (TCL_OK != tws_ParseRequest(interp, encoding, &ds, resultPtr)) {
        Tcl_DecrRefCount(resultPtr);
        Tcl_DStringFree(&ds);
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, resultPtr);
    Tcl_DecrRefCount(resultPtr);
    Tcl_DStringFree(&ds);
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