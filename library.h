/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#ifndef TWS_LIBRARY_H
#define TWS_LIBRARY_H

#include <tcl.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int Tws_Init(Tcl_Interp *interp);

#ifdef __cplusplus
}
#endif

#endif //TWS_LIBRARY_H
