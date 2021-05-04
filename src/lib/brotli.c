/**
 *
 */

#include "brotli.h"

int brotli_init(BrotliEncoderState **state) {
    *state = BrotliEncoderCreateInstance(NULL, NULL, NULL);
    if (*state == NULL) return -1;
    BrotliEncoderSetParameter(*state, BROTLI_PARAM_MODE, BROTLI_MODE_GENERIC);
    BrotliEncoderSetParameter(*state, BROTLI_PARAM_MODE, BROTLI_MODE_GENERIC);
    return 0;
}

int brotli_compress(BrotliEncoderState *state, const char *in, unsigned long *in_len, char *out, unsigned long *out_len, int finish) {
    int ret = BrotliEncoderCompressStream(state, finish ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_PROCESS,
            in_len, (const unsigned char**) &in, out_len, (unsigned char **) &out, NULL);
    return (ret == BROTLI_TRUE) ? 0 : -1;
}

int brotli_free(BrotliEncoderState *state) {
    BrotliEncoderDestroyInstance(state);
    return 0;
}
