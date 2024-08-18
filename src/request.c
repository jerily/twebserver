/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include "request.h"
#include "uri.h"
#include "base64.h"

static char hex_digits[] = "0123456789ABCDEF"; // A lookup table for hexadecimal digits

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

int tws_UrlDecode(Tcl_Encoding encoding, const char *value, Tcl_Size value_length, Tcl_DString *value_ds_ptr, int *error_num) {
    // check if url decoding is needed, value is not '\0' terminated
    const char *end = value + value_length;
    const char *p = tws_strpbrk(value, end, "%+");

    // no url decoding is needed
    if (p == NULL) {
        Tcl_DStringAppend(value_ds_ptr, value, value_length);
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
                *error_num = ERROR_URLDECODE_INVALID_SEQUENCE;
                return TCL_ERROR;
            }
            if (!tws_IsCharOfType(value[0], CHAR_HEX) || !tws_IsCharOfType(value[1], CHAR_HEX)) {
                Tcl_Free(valuePtr);
                *error_num = ERROR_URLDECODE_INVALID_SEQUENCE;
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

//    int dstLen = 2 * (q - valuePtr) + 1;
    char *ret = Tcl_ExternalToUtfDString(
            encoding,
            valuePtr,
            q - valuePtr,
            value_ds_ptr);
    if (ret == NULL) {
        Tcl_Free(valuePtr);
        *error_num = ERROR_URLDECODE_INVALID_SEQUENCE;
        return TCL_ERROR;
    }

    Tcl_Free(valuePtr);
    return TCL_OK;
}

int tws_UrlEncode(int enc_flags, const char *value, Tcl_Size value_length, Tcl_Obj **valuePtrPtr) {
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

static int tws_AddQueryStringParameter(Tcl_Encoding encoding, Tcl_HashTable *query_string_parameters_HT_ptr,
                                       Tcl_HashTable *multivalue_query_string_parameters_HT_ptr, const char *key, const char *value,
                                       Tcl_Size value_length, int *error_num) {

    Tcl_DString value_ds;
    Tcl_DStringInit(&value_ds);
    if (TCL_OK != tws_UrlDecode(encoding, value, value_length, &value_ds, error_num)) {
        Tcl_DStringFree(&value_ds);
        return TCL_ERROR;
    }

    // check if "key" already exists in "queryStringParameters"
    char *key_ptr = tws_strndup(key, value - key - 1);
    Tcl_HashEntry *existing_entry_ptr = Tcl_FindHashEntry(query_string_parameters_HT_ptr, key_ptr);

    if (existing_entry_ptr != NULL) {
        // check if "key" already exists in "multivalueQueryStringParameters"
        Tcl_HashEntry *existing_mv_entry_ptr = Tcl_FindHashEntry(query_string_parameters_HT_ptr, key_ptr);

        if (existing_mv_entry_ptr == NULL) {
            // it does not exist, create a new list and add the existing value from queryStringParameters
            Tcl_DString *existing_value_ds_ptr = Tcl_GetHashValue(existing_entry_ptr);
            Tcl_DString *multi_value_ds_ptr = (Tcl_DString *) Tcl_Alloc(sizeof(Tcl_DString));
            Tcl_DStringInit(multi_value_ds_ptr);
            Tcl_DStringAppendElement(multi_value_ds_ptr, Tcl_DStringValue(existing_value_ds_ptr));
            // append the new value to the list
            Tcl_DStringAppendElement(multi_value_ds_ptr, Tcl_DStringValue(&value_ds));
            int newEntry = 0;
            Tcl_SetHashValue(Tcl_CreateHashEntry(multivalue_query_string_parameters_HT_ptr, key_ptr, &newEntry), multi_value_ds_ptr);

        } else {
            Tcl_DString *multi_value_ds_ptr = Tcl_GetHashValue(existing_mv_entry_ptr);
            // append the new value to the list
            Tcl_DStringAppendElement(multi_value_ds_ptr, Tcl_DStringValue(&value_ds));
        }
    } else {
        Tcl_DString *value_ds_ptr = (Tcl_DString *) Tcl_Alloc(sizeof(Tcl_DString));
        Tcl_DStringInit(value_ds_ptr);
        Tcl_DStringAppend(value_ds_ptr, Tcl_DStringValue(&value_ds), Tcl_DStringLength(&value_ds));
        int newEntry = 0;
        Tcl_SetHashValue(Tcl_CreateHashEntry(query_string_parameters_HT_ptr, key_ptr, &newEntry), value_ds_ptr);

    }

    Tcl_DStringFree(&value_ds);
    Tcl_Free(key_ptr);
    return TCL_OK;
}

static void tws_FreeParseHashTable(Tcl_HashTable *ht_ptr) {
    Tcl_HashSearch search;
    Tcl_HashEntry *entry;
    for (entry = Tcl_FirstHashEntry(ht_ptr, &search); entry != NULL; entry = Tcl_NextHashEntry(&search)) {
        Tcl_DString *value_ds_ptr = Tcl_GetHashValue(entry);
        Tcl_DStringFree(value_ds_ptr);
        Tcl_Free((char *) value_ds_ptr);
    }
    Tcl_DeleteHashTable(ht_ptr);
}

int
tws_ParseQueryStringParameters(Tcl_Encoding encoding, const char *query_string, Tcl_Size query_string_length, Tcl_DString *parse_ds_ptr, int *error_num) {
    // parse "query_string" into "queryStringParameters" given that it is of the form "key1=value1&key2=value2&..."
//    Tcl_Obj *queryStringParametersPtr = Tcl_NewDictObj();
//    Tcl_IncrRefCount(queryStringParametersPtr);
//    Tcl_Obj *multiValueQueryStringParametersPtr = Tcl_NewDictObj();
//    Tcl_IncrRefCount(multiValueQueryStringParametersPtr);

    Tcl_HashTable query_string_parameters_HT;
    Tcl_InitHashTable(&query_string_parameters_HT, TCL_STRING_KEYS);

    Tcl_HashTable multi_value_query_string_parameters_HT;
    Tcl_InitHashTable(&multi_value_query_string_parameters_HT, TCL_STRING_KEYS);

//    Tcl_Size query_string_length;
//    const char *query_string = Tcl_GetStringFromObj(queryStringPtr, &query_string_length);
    const char *p = query_string;
    const char *end = query_string + query_string_length;
    while (p < end) {
        const char *key = p;
        const char *value = NULL;
        while (p < end && *p != '=') {
            p++;
        }
        if (p == end) {
//            Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
//            Tcl_DecrRefCount(queryStringParametersPtr);
            tws_FreeParseHashTable(&query_string_parameters_HT);
            tws_FreeParseHashTable(&multi_value_query_string_parameters_HT);

//            SetResult("query string parse error");
            *error_num = ERROR_NO_HEADER_KEY;
            return TCL_ERROR;
        }
        value = p + 1;
        while (p < end && *p != '&') {
            p++;
        }
        if (p == end) {
            if (TCL_OK !=
                tws_AddQueryStringParameter(encoding, &query_string_parameters_HT,
                                            &multi_value_query_string_parameters_HT, key,
                                            value, p - value, error_num)) {

//                Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
//                Tcl_DecrRefCount(queryStringParametersPtr);
                // todo: free hash table entries
                Tcl_DeleteHashTable(&query_string_parameters_HT);
                Tcl_DeleteHashTable(&multi_value_query_string_parameters_HT);

//                SetResult("query string parse error");
                return TCL_ERROR;
            }
            break;
        }
        if (TCL_OK !=
            tws_AddQueryStringParameter(encoding, &query_string_parameters_HT, &multi_value_query_string_parameters_HT,
                                        key,
                                        value, p - value, error_num)) {
//            Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
//            Tcl_DecrRefCount(queryStringParametersPtr);

            Tcl_DeleteHashTable(&query_string_parameters_HT);
            Tcl_DeleteHashTable(&multi_value_query_string_parameters_HT);

//            SetResult("query string parse error");
            return TCL_ERROR;
        }
        p++;
    }

    Tcl_DStringAppend(parse_ds_ptr, " queryStringParameters ", -1);
    Tcl_DStringStartSublist(parse_ds_ptr);
    Tcl_HashSearch search;
    Tcl_HashEntry *entry;
    for (entry = Tcl_FirstHashEntry(&query_string_parameters_HT, &search); entry != NULL;
         entry = Tcl_NextHashEntry(&search)) {
        const char *key = Tcl_GetHashKey(&query_string_parameters_HT, entry);
        Tcl_DString *value_ds_ptr = Tcl_GetHashValue(entry);
        Tcl_DStringAppend(parse_ds_ptr, key, -1);
        Tcl_DStringAppend(parse_ds_ptr, " ", -1);
        Tcl_DStringAppend(parse_ds_ptr, Tcl_DStringValue(value_ds_ptr), Tcl_DStringLength(value_ds_ptr));
    }
    Tcl_DStringEndSublist(parse_ds_ptr);

//    if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("queryStringParameters", -1), queryStringParametersPtr)) {
//        Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
//        Tcl_DecrRefCount(queryStringParametersPtr);
//        SetResult("query string parameters put error");
//        return TCL_ERROR;
//    }

    Tcl_DStringAppend(parse_ds_ptr, " multiValueQueryStringParameters ", -1);
    Tcl_DStringStartSublist(parse_ds_ptr);
    for (entry = Tcl_FirstHashEntry(&multi_value_query_string_parameters_HT, &search); entry != NULL;
         entry = Tcl_NextHashEntry(&search)) {
        const char *key = Tcl_GetHashKey(&multi_value_query_string_parameters_HT, entry);
        Tcl_DString *value = Tcl_GetHashValue(entry);
        Tcl_DStringAppendElement(parse_ds_ptr, key);
//        Tcl_DStringStartSublist(parse_ds_ptr);
        Tcl_DStringAppendElement(parse_ds_ptr, Tcl_DStringValue(value));
//        Tcl_DStringEndSublist(parse_ds_ptr);
    }
    Tcl_DStringEndSublist(parse_ds_ptr);

//    if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("multiValueQueryStringParameters", -1),
//                   multiValueQueryStringParametersPtr)) {
//        Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
//        Tcl_DecrRefCount(queryStringParametersPtr);
//        SetResult("multi value query string parameters put error");
//        return TCL_ERROR;
//    }
//    Tcl_DecrRefCount(multiValueQueryStringParametersPtr);
//    Tcl_DecrRefCount(queryStringParametersPtr);

    // todo: free hash table entries
    Tcl_DeleteHashTable(&query_string_parameters_HT);
    Tcl_DeleteHashTable(&multi_value_query_string_parameters_HT);
    return TCL_OK;
}

static int tws_ParsePathAndQueryString(Tcl_Encoding encoding, const char *url, Tcl_Size url_length,
                                       Tcl_DString *parse_ds_ptr, int *error_num) {
    // parse "path" and "queryStringParameters" from "url"
    const char *p2 = url;
    const char *end = url + url_length;
    while (p2 < end && *p2 != '\0') {
        if (*p2 == '?') {
            Tcl_Size path_length = p2 - url;
            Tcl_DString path_ds;
            Tcl_DStringInit(&path_ds);
            if (TCL_OK != tws_UrlDecode(encoding, url, path_length, &path_ds, error_num)) {
                Tcl_DStringFree(&path_ds);
                *error_num = ERROR_PATH_URL_DECODE;
                return TCL_ERROR;
            }

            Tcl_DStringAppend(parse_ds_ptr, " path ", -1);
            Tcl_DStringStartSublist(parse_ds_ptr);
            Tcl_DStringAppend(parse_ds_ptr, Tcl_DStringValue(&path_ds), Tcl_DStringLength(&path_ds));
            Tcl_DStringEndSublist(parse_ds_ptr);
            Tcl_DStringFree(&path_ds);

//            if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("path", -1), pathPtr)) {
//                Tcl_DecrRefCount(pathPtr);
//                SetResult("path dict put error");
//                return TCL_ERROR;
//            }
//            Tcl_DecrRefCount(pathPtr);

            Tcl_Size query_string_length = url + url_length - p2 - 1;
//            Tcl_Obj *queryStringPtr = Tcl_NewStringObj(p2 + 1, query_string_length);

            Tcl_DStringAppend(parse_ds_ptr, " queryString ", -1);
            Tcl_DStringStartSublist(parse_ds_ptr);
            Tcl_DStringAppend(parse_ds_ptr, p2 + 1, query_string_length);
            Tcl_DStringEndSublist(parse_ds_ptr);

//            Tcl_IncrRefCount(queryStringPtr);
//            if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("queryString", -1), queryStringPtr)) {
//                Tcl_DecrRefCount(queryStringPtr);
//                SetResult("queryString dict put error");
//                return TCL_ERROR;
//            }
            if (TCL_OK != tws_ParseQueryStringParameters(encoding, p2 + 1, query_string_length, parse_ds_ptr, error_num)) {
                return TCL_ERROR;
            }
//            Tcl_DecrRefCount(queryStringPtr);
            break;
        }
        p2++;
    }
    if (p2 == end) {
        Tcl_DStringAppend(parse_ds_ptr, " path ", -1);
        Tcl_DStringStartSublist(parse_ds_ptr);
        Tcl_DStringAppend(parse_ds_ptr, url, url_length);
        Tcl_DStringEndSublist(parse_ds_ptr);
        Tcl_DStringAppend(parse_ds_ptr, " queryString ", -1);
        Tcl_DStringAppend(parse_ds_ptr, "{}", -1);

//        if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("path", -1), Tcl_NewStringObj(url, url_length))) {
//            SetResult("path dict put error");
//            return TCL_ERROR;
//        }
//        if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("queryString", -1), Tcl_NewStringObj("", -1))) {
//            SetResult("queryString dict put error");
//            return TCL_ERROR;
//        }
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

static int tws_ParseRequestLine(Tcl_Encoding encoding, const char **currPtr, const char *end,
                                Tcl_DString *parse_ds_ptr, int *error_num) {
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
//        SetResult("request line parse error: no http method");
        *error_num = ERROR_NO_HTTP_METHOD;
        return TCL_ERROR;
    }

    // mark the end of the token and remember as "http_method"
    curr++;
//    char *http_method = strndup(p, curr - p);
//    http_method[curr - p - 1] = '\0';
    Tcl_Size http_method_length = curr - p - 1;

    // check that it is a valid http method:
    // GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE
    if (!tws_IsHttpMethod(p, http_method_length)) {
//        SetResult("request line parse error: invalid http method");
        *error_num = ERROR_INVALID_HTTP_METHOD;
        return TCL_ERROR;
    }

    Tcl_DStringAppend(parse_ds_ptr, "httpMethod ", -1);
    Tcl_DStringStartSublist(parse_ds_ptr);
    Tcl_DStringAppend(parse_ds_ptr, p, http_method_length);
    Tcl_DStringEndSublist(parse_ds_ptr);

//    if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("httpMethod", -1), Tcl_NewStringObj(p, http_method_length))) {
//        SetResult("request line parse error: dict put error");
//        return TCL_ERROR;
//    }

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
//        SetResult("request line parse error: no url");
        *error_num = ERROR_NO_URL;
        return TCL_ERROR;
    }

    // mark the end of the token and remember as "path"
    curr++;
//    char *url = strndup(p, curr - p);
//    url[curr - p - 1] = '\0';
    Tcl_Size url_length = curr - p - 1;

    Tcl_DStringAppend(parse_ds_ptr, " url ", -1);
    Tcl_DStringStartSublist(parse_ds_ptr);
    Tcl_DStringAppend(parse_ds_ptr, p, url_length);
    Tcl_DStringEndSublist(parse_ds_ptr);

//    if (TCL_OK != Tcl_DictObjPut(interp, resultPtr, Tcl_NewStringObj("url", -1), Tcl_NewStringObj(p, url_length))) {
//        SetResult("request line parse error: dict put error");
//        return TCL_ERROR;
//    }

    if (TCL_OK != tws_ParsePathAndQueryString(encoding, p, url_length, parse_ds_ptr, error_num)) {
        return TCL_ERROR;
    }

    // skip spaces until end of line denoted by "\r\n" or "\n"
    while (curr < end && CHARTYPE(space, *curr) != 0 && *curr != '\r' && *curr != '\n') {
        curr++;
    }
    p = curr;

    if (curr == end) {
//        SetResult("request line parse error: no version");
        *error_num = ERROR_NO_HTTP_VERSION;
        return TCL_ERROR;
    }

    // parse "version" if we have NOT reached the end of line
    if (*curr != '\r' && *curr != '\n') {

        // collect non-space chars as third token
        while (curr < end && CHARTYPE(space, *curr) == 0) {
            curr++;
        }
        if (curr == end) {
//            SetResult("request line parse error: while extracting version");
            *error_num = ERROR_NO_HTTP_VERSION;
            return TCL_ERROR;
        }

        if (!tws_IsHttpVersion(p, curr - p)) {
//            SetResult("request line parse error: invalid version");
            *error_num = ERROR_INVALID_HTTP_VERSION;
            return TCL_ERROR;
        }

        Tcl_DStringAppend(parse_ds_ptr, " version ", -1);
        Tcl_DStringStartSublist(parse_ds_ptr);
        Tcl_DStringAppend(parse_ds_ptr, p, curr - p);
        Tcl_DStringEndSublist(parse_ds_ptr);

        // mark the end of the token and remember as "version"
        curr++;

    }

    // skip newline chars
    while (curr < end && (*curr == '\r' || *curr == '\n')) {
        curr++;
    }
    *currPtr = curr;
    return TCL_OK;

}

static int tws_AddHeader(Tcl_HashTable *headers_HT_ptr, Tcl_HashTable *multi_value_headers_HT_ptr, const char *key,
                         const char *value) {

    // check if "key" already exists in "headers"
    Tcl_HashEntry *existing_entry_ptr = Tcl_FindHashEntry(headers_HT_ptr, key);
    if (existing_entry_ptr != NULL) {
        // check if "key" already exists in "multiValueHeaders"
        Tcl_HashEntry *existing_mv_entry_ptr = Tcl_FindHashEntry(multi_value_headers_HT_ptr, key);

        if (existing_mv_entry_ptr == NULL) {
            // it does not exist, create a new list and add the existing value from headers

            Tcl_DString *existing_value_ds_ptr = Tcl_GetHashValue(existing_entry_ptr);
            Tcl_DString *multi_value_ds_ptr = (Tcl_DString *) Tcl_Alloc(sizeof(Tcl_DString));
            Tcl_DStringInit(multi_value_ds_ptr);
            Tcl_DStringAppendElement(multi_value_ds_ptr, Tcl_DStringValue(existing_value_ds_ptr));
            // append the new value to the list
            Tcl_DStringAppendElement(multi_value_ds_ptr, value);
            int newEntry = 0;
            Tcl_SetHashValue(Tcl_CreateHashEntry(multi_value_headers_HT_ptr, key, &newEntry), multi_value_ds_ptr);
        } else {

            Tcl_DString *multi_value_ds_ptr = Tcl_GetHashValue(existing_mv_entry_ptr);
            // append the new value to the list
            Tcl_DStringAppendElement(multi_value_ds_ptr, value);
        }
    } else {
        Tcl_DString *value_ds_ptr = (Tcl_DString *) Tcl_Alloc(sizeof(Tcl_DString));
        Tcl_DStringInit(value_ds_ptr);
        Tcl_DStringAppend(value_ds_ptr, value, strlen(value));

        int newEntry = 0;
        Tcl_SetHashValue(Tcl_CreateHashEntry(headers_HT_ptr, key, &newEntry), value_ds_ptr);
    }

    return TCL_OK;
}

static int tws_ParseHeaders(const char **currPtr, const char *end, Tcl_HashTable *headers_HT_ptr,
                            Tcl_HashTable *multi_value_headers_HT_ptr, int *error_num) {

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
//            SetResult("ParseHeaders: no header key");
            *error_num = ERROR_NO_HEADER_KEY;
            return TCL_ERROR;
        }

        // mark the end of the token and remember as "key"
        curr++;
        Tcl_Size keylen = curr - p - 1;
        char *key = tws_strndup(p, keylen);
        // lowercase "key"
        for (int i = 0; i < keylen; i++) {
            key[i] = tolower(key[i]);
        }

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

        Tcl_Size valuelen = curr - p;
//        char *value = tws_strndup(p, valuelen);
        Tcl_DString value_ds;
        Tcl_DStringInit(&value_ds);
        Tcl_DStringAppend(&value_ds, p, valuelen);

        DBG2(printf("key=%s value=%s\n", key, Tcl_DStringValue(&value_ds)));

        // skip spaces until end of line denoted by "\r\n" or "\n"
        while (curr < end && CHARTYPE(space, *curr) != 0 && *curr != '\r' && *curr != '\n') {
            curr++;
        }

        // check if we reached the end
        if (curr == end) {
            if (TCL_OK != tws_AddHeader(headers_HT_ptr, multi_value_headers_HT_ptr, key, Tcl_DStringValue(&value_ds))) {
                Tcl_Free(key);
                Tcl_DStringFree(&value_ds);
                return TCL_ERROR;
            }
            Tcl_Free(key);
            Tcl_DStringFree(&value_ds);
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
            if (TCL_OK != tws_AddHeader(headers_HT_ptr, multi_value_headers_HT_ptr, key, Tcl_DStringValue(&value_ds))) {
//                Tcl_DecrRefCount(keyPtr);
//                Tcl_DecrRefCount(valuePtr);
//                SetResult("ParseHeaders: failed adding header (2)");
                Tcl_Free(key);
                Tcl_DStringFree(&value_ds);
                return TCL_ERROR;
            }
//            Tcl_DecrRefCount(keyPtr);
//            Tcl_DecrRefCount(valuePtr);
            Tcl_Free(key);
            Tcl_DStringFree(&value_ds);
            break;
        }

        // check if the line starts with a space, if so, it is a continuation of the previous header
        while (curr < end && *curr == ' ') {
            DBG2(printf("continuation curr=%p end=%p intchar=%d\n", curr, end, (int) curr[0]));
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
            Tcl_Size continuation_valuelen = curr - p - 1;
            char *continuation_value = tws_strndup(p, continuation_valuelen);
            // append the continuation value to the previous value
            Tcl_DStringAppend(&value_ds, continuation_value, continuation_valuelen);
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

        if (TCL_OK != tws_AddHeader(headers_HT_ptr, multi_value_headers_HT_ptr, key, Tcl_DStringValue(&value_ds))) {
            Tcl_Free(key);
            Tcl_DStringFree(&value_ds);
            return TCL_ERROR;
        }
        Tcl_Free(key);
        Tcl_DStringFree(&value_ds);

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

int tws_ParseBody(tws_conn_t *conn, const char *curr, const char *end, int *error_num) {

    Tcl_Size content_length = end - curr;

    const char *content_type = conn->content_type;
    size_t content_type_length = strnlen(content_type, sizeof(conn->content_type));

    DBG2(printf("content_type: %s\n", content_type));

    int base64_encode_it = 0;
    if (content_type_length > 0) {
//        Tcl_Size content_type_length;
//        const char *content_type = Tcl_GetStringFromObj(content_type_ptr, &content_type_length);
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
//                    if (TCL_OK != Tcl_DictObjPut(interp, result_ptr, Tcl_NewStringObj("multipartBoundary", -1), Tcl_NewStringObj(p, content_type_end - p))) {
//                        SetResult("dict put error");
//                        return TCL_ERROR;
//                    }
                    Tcl_DStringAppend(&conn->parse_ds, " multipartBoundary ", -1);
                    Tcl_DStringAppend(&conn->parse_ds, p, content_type_end - p);
                }
            }
        }
    }

//    if (TCL_OK != Tcl_DictObjPut(interp, result_ptr, Tcl_NewStringObj("isBase64Encoded", -1), Tcl_NewBooleanObj(base64_encode_it))) {
//        SetResult("dict put error");
//        return TCL_ERROR;
//    }

    Tcl_DStringAppend(&conn->parse_ds, " isBase64Encoded ", -1);
    Tcl_DStringAppend(&conn->parse_ds, base64_encode_it ? "1" : "0", 1);

    if (base64_encode_it) {
        // base64 encode the body and remember as "body"
        char *body = Tcl_Alloc(content_length * 2);
        Tcl_Size body_length;
        if (base64_encode(curr, content_length, body, &body_length)) {
            Tcl_Free(body);
//            SetResult("base64_encode failed");
            *error_num = ERROR_BASE64_ENCODE_BODY;
            return TCL_ERROR;
        }
//        if (TCL_OK != Tcl_DictObjPut(interp, result_ptr, Tcl_NewStringObj("body", -1), Tcl_NewStringObj(body, body_length))) {
//            Tcl_Free(body);
//            SetResult("dict put error");
//            return TCL_ERROR;
//        }

        Tcl_DStringAppend(&conn->parse_ds, " body ", -1);
        Tcl_DStringStartSublist(&conn->parse_ds);
        Tcl_DStringAppend(&conn->parse_ds, body, body_length);
        Tcl_DStringEndSublist(&conn->parse_ds);

        Tcl_Free(body);
    } else {
        // mark the end of the token and remember as "body"
        char *body = tws_strndup(curr, content_length);

        Tcl_DStringAppend(&conn->parse_ds, " body ", -1);
        Tcl_DStringStartSublist(&conn->parse_ds);
        Tcl_DStringAppend(&conn->parse_ds, body, content_length);
        Tcl_DStringEndSublist(&conn->parse_ds);

        Tcl_Free(body);
    }

    return TCL_OK;
}

int tws_ParseRequest(tws_conn_t *conn, int *error_num) {

    Tcl_Encoding encoding = conn->encoding;
    Tcl_DString *dsPtr = &conn->inout_ds;
    Tcl_DString *parse_ds_ptr = &conn->parse_ds;
    Tcl_Size *offset = &conn->top_part_offset;

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
    if (TCL_OK != tws_ParseRequestLine(encoding, &curr, end, parse_ds_ptr, error_num)) {
        return TCL_ERROR;
    }
    DBG2(printf("parse dstring after parse request line: %s\n", Tcl_DStringValue(parse_ds_ptr)));

    Tcl_HashTable headers_HT;
    Tcl_InitHashTable(&headers_HT, TCL_STRING_KEYS);
    Tcl_HashTable multi_value_headers_HT;
    Tcl_InitHashTable(&multi_value_headers_HT, TCL_STRING_KEYS);

//    Tcl_Obj *headersPtr = Tcl_NewDictObj();
//    Tcl_IncrRefCount(headersPtr);
//    Tcl_Obj *multiValueHeadersPtr = Tcl_NewDictObj();
//    Tcl_IncrRefCount(multiValueHeadersPtr);

    if (TCL_OK != tws_ParseHeaders(&curr, end, &headers_HT, &multi_value_headers_HT, error_num)) {
//        Tcl_DecrRefCount(multiValueHeadersPtr);
//        Tcl_DecrRefCount(headersPtr);
        tws_FreeParseHashTable(&headers_HT);
        tws_FreeParseHashTable(&multi_value_headers_HT);
        return TCL_ERROR;
    }

    // headers
    Tcl_DStringAppend(parse_ds_ptr, " headers ", -1);
    Tcl_DStringStartSublist(parse_ds_ptr);
    Tcl_HashSearch search;
    Tcl_HashEntry *entry;
    for (entry = Tcl_FirstHashEntry(&headers_HT, &search); entry != NULL; entry = Tcl_NextHashEntry(&search)) {
        const char *key = Tcl_GetHashKey(&headers_HT, entry);
        Tcl_DString *value_ds_ptr = Tcl_GetHashValue(entry);
        Tcl_DStringAppendElement(parse_ds_ptr, key);
        Tcl_DStringAppendElement(parse_ds_ptr, Tcl_DStringValue(value_ds_ptr));
    }
    Tcl_DStringEndSublist(parse_ds_ptr);

    // multiValueHeaders
    Tcl_DStringAppend(parse_ds_ptr, " multiValueHeaders ", -1);
    Tcl_DStringStartSublist(parse_ds_ptr);
    for (entry = Tcl_FirstHashEntry(&multi_value_headers_HT, &search); entry != NULL; entry = Tcl_NextHashEntry(&search)) {
        const char *key = Tcl_GetHashKey(&multi_value_headers_HT, entry);
        Tcl_DString *value = Tcl_GetHashValue(entry);
        Tcl_DStringAppendElement(parse_ds_ptr, key);
        Tcl_DStringAppendElement(parse_ds_ptr, Tcl_DStringValue(value));
    }
    Tcl_DStringEndSublist(parse_ds_ptr);

    // content-length
    Tcl_HashEntry *content_length_entry_ptr = Tcl_FindHashEntry(&headers_HT, "content-length");
    if (content_length_entry_ptr) {
        Tcl_DString *content_length_ds_ptr = Tcl_GetHashValue(content_length_entry_ptr);
        conn->content_length = strtol(Tcl_DStringValue(content_length_ds_ptr), NULL, 10);
    }

    // keepalive
    if (conn->accept_ctx->server->keepalive) {
        if (TCL_OK != tws_ParseConnectionKeepalive(&headers_HT, &conn->keepalive)) {
            return TCL_ERROR;
        }
    }

    // compression
    if (conn->accept_ctx->server->gzip) {
        if (TCL_OK != tws_ParseAcceptEncoding(&headers_HT, &conn->compression)) {
            return TCL_ERROR;
        }
    }

    // content-type
    Tcl_HashEntry *content_type_entry_ptr = Tcl_FindHashEntry(&headers_HT, "content-type");
    if (content_type_entry_ptr) {
        Tcl_DString *content_type_ds_ptr = Tcl_GetHashValue(content_type_entry_ptr);
        Tcl_Size content_type_length = Tcl_DStringLength(content_type_ds_ptr);
        const char *content_type = Tcl_DStringValue(content_type_ds_ptr);
        size_t n = MIN(MAX_CONTENT_TYPE_SIZE - 1, content_type_length);
        memcpy(conn->content_type, content_type, n);
        conn->content_type[n] = '\0';
    }

    tws_FreeParseHashTable(&headers_HT);
    tws_FreeParseHashTable(&multi_value_headers_HT);

    *offset = curr - request;
    return TCL_OK;
}

// gzip is enabled q-values greater than 0.001
static int tws_GzipAcceptEncoding(const char *accept_encoding, Tcl_Size accept_encoding_length) {
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

int tws_ParseConnectionKeepalive(Tcl_HashTable *headers_HT_ptr, int *keepalive) {
//    Tcl_Obj *connectionPtr;
//    Tcl_Obj *connectionKeyPtr = Tcl_NewStringObj("connection", -1);
//    Tcl_IncrRefCount(connectionKeyPtr);
//    if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, connectionKeyPtr, &connectionPtr)) {
//        Tcl_DecrRefCount(connectionKeyPtr);
//        SetResult("error reading dict");
//        return TCL_ERROR;
//    }
//    Tcl_DecrRefCount(connectionKeyPtr);
//    if (!connectionPtr) {
//        return TCL_OK;
//    }

    Tcl_HashEntry *connection_entry_ptr = Tcl_FindHashEntry(headers_HT_ptr, "connection");
    if (!connection_entry_ptr) {
        return TCL_OK;
    }

    Tcl_DString *connection_ds_ptr = Tcl_GetHashValue(connection_entry_ptr);
    Tcl_Size connection_length = Tcl_DStringLength(connection_ds_ptr);
    const char *connection = Tcl_DStringValue(connection_ds_ptr);

//    Tcl_Size connection_length;
//    const char *connection = Tcl_GetStringFromObj(connectionPtr, &connection_length);
    if (connection_length == 10 && strncmp(connection, "keep-alive", 10) == 0) {
        *keepalive = 1;
    }
    return TCL_OK;
}

int tws_ParseAcceptEncoding(Tcl_HashTable *headers_HT_ptr, tws_compression_method_t *compression) {
    // parse "Accept-Encoding" header and set "compression" accordingly

//    Tcl_Obj *acceptEncodingPtr;
//    Tcl_Obj *acceptEncodingKeyPtr = Tcl_NewStringObj("accept-encoding", -1);
//    Tcl_IncrRefCount(acceptEncodingKeyPtr);
//    if (TCL_OK != Tcl_DictObjGet(interp, headersPtr, acceptEncodingKeyPtr, &acceptEncodingPtr)) {
//        Tcl_DecrRefCount(acceptEncodingKeyPtr);
//        SetResult("error reading dict");
//        return TCL_ERROR;
//    }
//    Tcl_DecrRefCount(acceptEncodingKeyPtr);
//    if (!acceptEncodingPtr) {
//        *compression = NO_COMPRESSION;
//        return TCL_OK;
//    }

    Tcl_HashEntry *accept_encoding_entry_ptr = Tcl_FindHashEntry(headers_HT_ptr, "accept-encoding");
    if (!accept_encoding_entry_ptr) {
        *compression = NO_COMPRESSION;
        return TCL_OK;
    }

    Tcl_DString *acceptEncoding_ds_ptr = Tcl_GetHashValue(accept_encoding_entry_ptr);
    Tcl_Size accept_encoding_length = Tcl_DStringLength(acceptEncoding_ds_ptr);
    const char *accept_encoding = Tcl_DStringValue(acceptEncoding_ds_ptr);

//    Tcl_Size accept_encoding_length;
//    const char *accept_encoding = Tcl_GetStringFromObj(acceptEncodingPtr, &accept_encoding_length);

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

int tws_ParseTopPart(tws_conn_t *conn, int *error_num) {
    DBG2(printf("parse top part: start %d\n", conn->client));

    if (TCL_OK != tws_ParseRequest(conn, error_num)) {
        return TCL_ERROR;
    }

    return TCL_OK;
}

int tws_ParseBottomPart(tws_conn_t *conn, int *error_num) {
    DBG2(printf("parse bottom part\n"));

    if (conn->content_length > 0) {
        const char *remaining_unprocessed_ptr = Tcl_DStringValue(&conn->inout_ds) + conn->top_part_offset;
        const char *end = Tcl_DStringValue(&conn->inout_ds) + Tcl_DStringLength(&conn->inout_ds);
        if (TCL_OK != tws_ParseBody(conn, remaining_unprocessed_ptr, end, error_num)) {
            return TCL_ERROR;
        }
    }

    return TCL_OK;
    handle_error:
    return TCL_ERROR;
}
