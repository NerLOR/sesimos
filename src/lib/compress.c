/**
 * Necronda Web Server
 * Compression interface
 * src/lib/compress.c
 * Lorenz Stechauner, 2021-05-05
 */

#include "compress.h"

#include <malloc.h>
#include <errno.h>


int compress_init(compress_ctx *ctx, int mode) {
    ctx->gzip = NULL;
    ctx->brotli = NULL;
    ctx->mode = 0;
    int ret;
    if (mode & COMPRESS_GZ) {
        ctx->mode |= COMPRESS_GZ;
        ctx->gzip = malloc(sizeof(z_stream));
        ctx->gzip->zalloc = Z_NULL;
        ctx->gzip->zfree = Z_NULL;
        ctx->gzip->opaque = Z_NULL;
        ret = deflateInit2(ctx->gzip, COMPRESS_LEVEL_GZIP, Z_DEFLATED, 15 + 16, 9, Z_DEFAULT_STRATEGY);
        if (ret != Z_OK) return -1;
    }
    if (mode & COMPRESS_BR) {
        ctx->mode |= COMPRESS_BR;
        ctx->brotli = BrotliEncoderCreateInstance(NULL, NULL, NULL);
        if (ctx->brotli == NULL) return -1;
        BrotliEncoderSetParameter(ctx->brotli, BROTLI_PARAM_MODE, BROTLI_MODE_GENERIC);
        BrotliEncoderSetParameter(ctx->brotli, BROTLI_PARAM_QUALITY, COMPRESS_LEVEL_BROTLI);
    }
    return 0;
}

int compress_compress(compress_ctx *ctx, const char *in, unsigned long *in_len, char *out, unsigned long *out_len, int finish) {
    if ((ctx->mode & COMPRESS_GZ) && (ctx->mode & COMPRESS_BR)) {
        errno = EINVAL;
        return -1;
    }
    return compress_compress_mode(ctx, ctx->mode, in, in_len, out, out_len, finish);
}

int compress_compress_mode(compress_ctx *ctx, int mode, const char *in, unsigned long *in_len, char *out, unsigned long *out_len, int finish) {
    if ((mode & COMPRESS_GZ) && (mode & COMPRESS_BR)) {
        errno = EINVAL;
        return -1;
    } else if (mode & COMPRESS_GZ) {
        ctx->gzip->next_in = (unsigned char*) in;
        ctx->gzip->avail_in = *in_len;
        ctx->gzip->next_out = (unsigned char*) out;
        ctx->gzip->avail_out = *out_len;
        int ret = deflate(ctx->gzip, finish ? Z_FINISH : Z_NO_FLUSH);
        *in_len = ctx->gzip->avail_in;
        *out_len = ctx->gzip->avail_out;
        return ret;
    } else if (mode & COMPRESS_BR) {
        int ret = BrotliEncoderCompressStream(ctx->brotli, finish ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_PROCESS,
                                              in_len, (const unsigned char**) &in, out_len, (unsigned char **) &out, NULL);
        return (ret == BROTLI_TRUE) ? 0 : -1;
    } else {
        errno = EINVAL;
        return -2;
    }
}

int compress_free(compress_ctx *ctx) {
    if (ctx->gzip != NULL) {
        deflateEnd(ctx->gzip);
        free(ctx->gzip);
        ctx->gzip = NULL;
    }
    if (ctx->brotli != NULL) {
        BrotliEncoderDestroyInstance(ctx->brotli);
        ctx->brotli = NULL;
    }
    ctx->mode = 0;
    return 0;
}
