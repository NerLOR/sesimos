/**
 * sesimos - secure, simple, modern web server
 * @brief Compression interface (header file)
 * @file src/lib/compress.h
 * @author Lorenz Stechauner
 * @date 2021-05-05
 */

#ifndef SESIMOS_COMPRESS_H
#define SESIMOS_COMPRESS_H

#include <zlib.h>
#include <brotli/encode.h>

#define COMPRESS_LEVEL_GZIP 9
#define COMPRESS_LEVEL_BROTLI BROTLI_MAX_QUALITY

#define COMPRESS_GZ 1
#define COMPRESS_BR 2
#define COMPRESS 3

typedef struct {
    int mode;
    z_stream *gzip;
    BrotliEncoderState *brotli;
} compress_ctx;

int compress_init(compress_ctx *ctx, int mode);

int compress_compress(compress_ctx *ctx, const char *in, unsigned long *in_len, char *out, unsigned long *out_len,
                      int finish);

int compress_compress_mode(compress_ctx *ctx, int mode, const char *in, unsigned long *in_len, char *out,
                           unsigned long *out_len, int finish);

int compress_free(compress_ctx *ctx);

#endif //SESIMOS_COMPRESS_H
