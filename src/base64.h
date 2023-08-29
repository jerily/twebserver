#ifndef TWEBSERVER_BASE64_H
#define TWEBSERVER_BASE64_H

#include <stddef.h>
#include <stdint.h>

int base64_encode(const char *input, size_t input_length, char *output, size_t *output_length);
int base64_decode(const char* input, size_t input_length, char *output, size_t *output_length);

#endif //TWEBSERVER_BASE64_H
