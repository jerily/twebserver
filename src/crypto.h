/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#ifndef TWEBSERVER_CRYPTO_H
#define TWEBSERVER_CRYPTO_H

#include <tcl.h>
#include "common.h"

ObjCmdProc(tws_RandomBytesCmd);
ObjCmdProc(tws_Sha1Cmd);
ObjCmdProc(tws_Sha256Cmd);
ObjCmdProc(tws_Sha512Cmd);
ObjCmdProc(tws_HexEncodeCmd);
ObjCmdProc(tws_HexDecodeCmd);

#endif //TWEBSERVER_CRYPTO_H
