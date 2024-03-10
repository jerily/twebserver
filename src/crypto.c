/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include "crypto.h"
#include <openssl/rand.h>


int tws_RandomBytesCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "RandomBytesCmd\n"));
    CheckArgs(2, 2, 1, "num_bytes");

    int num_bytes;
    if (TCL_OK != Tcl_GetIntFromObj(interp, objv[1], &num_bytes) || num_bytes < 0) {
        SetResult("num_bytes must be an integer >= 0");
        return TCL_ERROR;
    }

    // Allocate memory for the array
    unsigned char *output = (unsigned char *) Tcl_Alloc(num_bytes);

    // Check if the allocation was successful
    if (output == NULL) {
        SetResult("Could not allocate memory for random bytes");
        return TCL_ERROR;
    }

    // Call RAND_bytes with the array and num_bytes as arguments
    int status = RAND_bytes(output, num_bytes);

    // Check if the return value was 1, indicating success
    if (status != 1) {
        Tcl_Free((char *) output);
        SetResult("RAND_bytes failed");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(output, num_bytes));
    Tcl_Free((char *) output);
    return TCL_OK;
}

int tws_Sha1Cmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "Sha1Cmd\n"));
    CheckArgs(2, 2, 1, "bytes");

    Tcl_Size num_bytes;
    unsigned char *bytes = Tcl_GetByteArrayFromObj(objv[1], &num_bytes);

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(bytes, num_bytes, hash);

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(hash, SHA_DIGEST_LENGTH));
    return TCL_OK;
}

int tws_Sha256Cmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "Sha256Cmd\n"));
    CheckArgs(2, 2, 1, "bytes");

    Tcl_Size num_bytes;
    unsigned char *bytes = Tcl_GetByteArrayFromObj(objv[1], &num_bytes);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(bytes, num_bytes, hash);

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(hash, SHA256_DIGEST_LENGTH));
    return TCL_OK;
}

int tws_Sha512Cmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "Sha512Cmd\n"));
    CheckArgs(2, 2, 1, "bytes");

    Tcl_Size num_bytes;
    unsigned char *bytes = Tcl_GetByteArrayFromObj(objv[1], &num_bytes);

    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(bytes, num_bytes, hash);

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(hash, SHA512_DIGEST_LENGTH));
    return TCL_OK;
}

int tws_HexEncodeCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "HexEncodeCmd\n"));
    CheckArgs(2, 2, 1, "bytes");

    Tcl_Size num_bytes;
    unsigned char *bytes = Tcl_GetByteArrayFromObj(objv[1], &num_bytes);

    const char sep = '\0';
    Tcl_Size str_n = num_bytes * 2 + 1;
    char *str = Tcl_Alloc(str_n);
    if (!OPENSSL_buf2hexstr_ex(str, str_n, NULL, bytes, num_bytes, sep)) {
        Tcl_Free(str);
        SetResult("Could not encode bytes to hex string");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewStringObj(str, str_n - 1));
    Tcl_Free(str);
    return TCL_OK;
}

int tws_HexDecodeCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "HexDecodeCmd\n"));
    CheckArgs(2, 2, 1, "hex_encoded_string");

    Tcl_Size hex_length;
    const char *hex_str = Tcl_GetStringFromObj(objv[1], &hex_length);

    const char sep = '\0';
    Tcl_Size buf_n = hex_length / 2;
    unsigned char *buf = (unsigned char *) Tcl_Alloc(buf_n);

    if (!OPENSSL_hexstr2buf_ex(buf, buf_n, NULL, hex_str, sep)) {
        Tcl_Free((char *) buf);
        SetResult("Could not decode hex string");
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(buf, buf_n));
    Tcl_Free((char *) buf);
    return TCL_OK;
}