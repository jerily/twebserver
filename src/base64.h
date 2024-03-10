#ifndef TWEBSERVER_BASE64_H
#define TWEBSERVER_BASE64_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"

int base64_encode(const char *input, Tcl_Size input_length, char *output, Tcl_Size *output_length);
int base64_decode(const char* input, Tcl_Size input_length, char *output, Tcl_Size *output_length);

#endif //TWEBSERVER_BASE64_H
