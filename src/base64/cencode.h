//
// Created by phi on 8/29/23.
//

#ifndef TWEBSERVER_CENCODE_H
#define TWEBSERVER_CENCODE_H

#include <stddef.h>

typedef enum
{
    step_A, step_B, step_C
} base64_encodestep;

#define BASE64_CENC_DEFCPL	0

typedef struct
{
    size_t stepcount;
    size_t chars_per_line;

    base64_encodestep step;

    int cflags;
    char result;
} base64_encodestate;

extern void base64_init_encodestate(base64_encodestate* state_in);
extern size_t base64_encode_length(size_t plain_len, base64_encodestate* state_in);
extern char base64_encode_value(signed char value_in);
extern size_t base64_encode_block(const void* plaintext_in, const size_t length_in, char* code_out, base64_encodestate* state_in);
extern size_t base64_encode_blockend(char* code_out, base64_encodestate* state_in);

#endif //TWEBSERVER_CENCODE_H
