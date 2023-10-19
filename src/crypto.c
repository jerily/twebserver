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
    return TCL_OK;
}

int tws_Sha256Cmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DBG(fprintf(stderr, "Sha256Cmd\n"));
    CheckArgs(2, 2, 1, "bytes");

    int num_bytes;
    unsigned char *bytes = Tcl_GetByteArrayFromObj(objv[1], &num_bytes);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(bytes, num_bytes, hash);

    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(hash, SHA256_DIGEST_LENGTH));
    return TCL_OK;
}