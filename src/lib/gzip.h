/**
 *
 */

#ifndef NECRONDA_SERVER_GZIP_H
#define NECRONDA_SERVER_GZIP_H

#include <zlib.h>

#define GZIP_LEVEL 9

int gzip_init(z_stream *stream);

int gzip_compress(z_stream *stream, const char *in, unsigned long *in_len, char *out, unsigned long *out_len, int finish);

int gzip_free(z_stream *stream);

#endif //NECRONDA_SERVER_GZIP_H
