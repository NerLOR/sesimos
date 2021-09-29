/**
 * Necronda Web Server
 * Utilities (header file)
 * src/lib/utils.h
 * Lorenz Stechauner, 2020-12-03
 */

#ifndef NECRONDA_SERVER_UTILS_H
#define NECRONDA_SERVER_UTILS_H

#include <stdio.h>

#define ERR_STR "\x1B[1;31m"
#define CLR_STR "\x1B[0m"
#define BLD_STR "\x1B[1m"
#define WRN_STR "\x1B[1;33m"
#define BLUE_STR "\x1B[34m"
#define HTTP_STR "\x1B[1;31m"
#define HTTPS_STR "\x1B[1;32m"

extern char *log_prefix;

#define out_1(fmt) fprintf(stdout, "%s" fmt "\n", log_prefix)
#define out_2(fmt, args...) fprintf(stdout, "%s" fmt "\n", log_prefix, args)

#define out_x(x, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, FUNC, ...) FUNC

#define print(...) out_x(, ##__VA_ARGS__, out_2(__VA_ARGS__), out_2(__VA_ARGS__), out_2(__VA_ARGS__), \
                         out_2(__VA_ARGS__), out_2(__VA_ARGS__), out_2(__VA_ARGS__), out_2(__VA_ARGS__), \
                         out_2(__VA_ARGS__), out_1(__VA_ARGS__))


char *format_duration(unsigned long micros, char *buf);

int url_encode_component(const char *str, char *enc, long *size);

int url_encode(const char *str, char *enc, long *size);

int url_decode(const char *str, char *dec, long *size);

int mime_is_compressible(const char *type);

int strcpy_rem_webroot(char *dst, const char *str, long len, const char *webroot);

#endif //NECRONDA_SERVER_UTILS_H
