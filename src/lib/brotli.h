/**
 *
 */

#include <brotli/encode.h>

int brotli_init(BrotliEncoderState **state);

int brotli_compress(BrotliEncoderState *state, const char *in, unsigned long *in_len, char *out, unsigned long *out_len, int finish);

int brotli_free(BrotliEncoderState *state);
