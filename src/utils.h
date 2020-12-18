/**
 * Necronda Web Server
 * Utilities (header file)
 * src/utils.h
 * Lorenz Stechauner, 2020-12-03
 */

#ifndef NECRONDA_SERVER_UTILS_H
#define NECRONDA_SERVER_UTILS_H

char *log_prefix;

#define out_1(fmt) fprintf(parent_stdout, "%s" fmt "\n", log_prefix)
#define out_2(fmt, args...) fprintf(parent_stdout, "%s" fmt "\n", log_prefix, args)

#define out_x(x, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, FUNC, ...) FUNC

#define print(...) out_x(, ##__VA_ARGS__, out_2(__VA_ARGS__), out_2(__VA_ARGS__), out_2(__VA_ARGS__), \
                         out_2(__VA_ARGS__), out_2(__VA_ARGS__), out_2(__VA_ARGS__), out_2(__VA_ARGS__), \
                         out_2(__VA_ARGS__), out_1(__VA_ARGS__))


char *format_duration(unsigned long micros, char *buf);

int url_encode(const char *str, char *enc, ssize_t *size);

int encode_url(const char *str, char *enc, ssize_t *size);

int url_decode(const char *str, char *dec, ssize_t *size);

#endif //NECRONDA_SERVER_UTILS_H
