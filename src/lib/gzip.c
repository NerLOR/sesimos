/**
 *
 */

#include "gzip.h"

int gzip_init(z_stream *stream) {
    stream->zalloc = Z_NULL;
    stream->zfree = Z_NULL;
    stream->opaque = Z_NULL;
    int ret = deflateInit2(stream, GZIP_LEVEL, Z_DEFLATED, 15 + 16, 9, Z_DEFAULT_STRATEGY);
    return (ret == Z_OK) ? 0 : -1;
}

int gzip_compress(z_stream *stream, const char *in, unsigned long *in_len, char *out, unsigned long *out_len, int finish) {
    stream->next_in = (unsigned char*) in;
    stream->avail_in = *in_len;
    stream->next_out = (unsigned char*) out;
    stream->avail_out = *out_len;
    int ret = deflate(stream, finish ? Z_FINISH : Z_NO_FLUSH);
    *in_len = stream->avail_in;
    *out_len = stream->avail_out;
    return ret;
}

int gzip_free(z_stream *stream) {
    return deflateEnd(stream);
}
