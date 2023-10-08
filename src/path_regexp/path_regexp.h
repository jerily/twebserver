/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#ifndef TWEBSERVER_PATH_REGEXP_H
#define TWEBSERVER_PATH_REGEXP_H

#include <tcl.h>
#include "../common.h"

enum {
    STRICT_MATCH = 1,
    START_MATCH = 2,
    END_MATCH = 4,
    NOCASE_MATCH = 8,
};

int tws_PathToRegExp(Tcl_Interp *interp, const char *path, int path_len, int flags, Tcl_Obj **keysPtr, char **pattern);

#endif //TWEBSERVER_PATH_REGEXP_H
