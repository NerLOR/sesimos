/**
 * sesimos - secure, simple, modern web server
 * @brief Compression interface
 * @file src/lib/compress.c
 * @author Lorenz Stechauner
 * @date 2021-05-05
 */

#include "compress.h"

#include <errno.h>


int compress_init(compress_ctx *ctx, int mode) {
    ctx->brotli = NULL;

    if (mode & COMPRESS_GZ) {
        ctx->mode |= COMPRESS_GZ;
        ctx->gzip.zalloc = Z_NULL;
        ctx->gzip.zfree = Z_NULL;
        ctx->gzip.opaque = Z_NULL;
        ctx->gzip.data_type = (mode & COMPRESS_UTF8) ? Z_TEXT : Z_UNKNOWN;
        if (deflateInit2(&ctx->gzip, COMPRESS_LEVEL_GZIP, Z_DEFLATED, 15 + 16, 9, Z_DEFAULT_STRATEGY) != Z_OK)
            return -1;
    }

    if (mode & COMPRESS_BR) {
        ctx->mode |= COMPRESS_BR;
        if ((ctx->brotli = BrotliEncoderCreateInstance(NULL, NULL, NULL)) == NULL)
            return -1;
        BrotliEncoderSetParameter(ctx->brotli, BROTLI_PARAM_MODE, (mode & COMPRESS_UTF8) ? BROTLI_MODE_TEXT : ((mode & COMPRESS_WOFF) ? BROTLI_MODE_FONT : BROTLI_MODE_GENERIC));
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

static int compress_brotli(BrotliEncoderState *ctx, const char *in, unsigned long *in_len, char *out, unsigned long *out_len, int finish) {
    int ret = BrotliEncoderCompressStream(
            ctx, finish ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_PROCESS,
            in_len, (const unsigned char**) &in, out_len, (unsigned char **) &out, NULL);
    return (ret == BROTLI_TRUE) ? 0 : -1;
}

static int compress_gzip(z_stream *gzip, const char *in, unsigned long *in_len, char *out, unsigned long *out_len, int finish) {
    gzip->next_in = (unsigned char*) in;
    gzip->avail_in = *in_len;
    gzip->next_out = (unsigned char*) out;
    gzip->avail_out = *out_len;
    int ret = deflate(gzip, finish ? Z_FINISH : Z_NO_FLUSH);
    *in_len = gzip->avail_in;
    *out_len = gzip->avail_out;
    return ret;
}

int compress_compress_mode(compress_ctx *ctx, int mode, const char *in, unsigned long *in_len, char *out, unsigned long *out_len, int finish) {
    if ((mode & COMPRESS_GZ) && (mode & COMPRESS_BR)) {
        errno = EINVAL;
        return -1;
    } else if (mode & COMPRESS_GZ) {
        return compress_gzip(&ctx->gzip, in, in_len, out, out_len, finish);
    } else if (mode & COMPRESS_BR) {
        return compress_brotli(ctx->brotli, in, in_len, out, out_len, finish);
    } else {
        errno = EINVAL;
        return -1;
    }
}

int compress_free(compress_ctx *ctx) {
    if (ctx->brotli != NULL) {
        BrotliEncoderDestroyInstance(ctx->brotli);
        ctx->brotli = NULL;
    }
    if (ctx->mode & COMPRESS_GZ) {
        deflateEnd(&ctx->gzip);
    }
    ctx->mode = 0;
    return 0;
}
