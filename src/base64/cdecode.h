#ifndef TWEBSERVER_CDECODE_H
#define TWEBSERVER_CDECODE_H

#include <stddef.h>

typedef enum
{
    step_a, step_b, step_c, step_d
} base64_decodestep;

typedef struct
{
    base64_decodestep step;
    char plainchar;
} base64_decodestate;

extern void base64_init_decodestate(base64_decodestate* state_in);
extern size_t base64_decode_maxlength(size_t encode_len);
extern int base64_decode_value(signed char value_in);
extern size_t base64_decode_block(const char* code_in, const size_t length_in, void* plaintext_out, base64_decodestate* state_in);

#endif //TWEBSERVER_CDECODE_H
