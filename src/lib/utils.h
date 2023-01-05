/**
 * sesimos - secure, simple, modern web server
 * @brief Utilities (header file)
 * @file src/lib/utils.h
 * @author Lorenz Stechauner
 * @date 2020-12-03
 */

#ifndef SESIMOS_UTILS_H
#define SESIMOS_UTILS_H

#include <stdio.h>

#define ERR_STR "\x1B[1;31m"
#define CLR_STR "\x1B[0m"
#define BLD_STR "\x1B[1m"
#define WRN_STR "\x1B[1;33m"
#define BLUE_STR "\x1B[34m"
#define HTTP_STR "\x1B[1;31m"
#define HTTPS_STR "\x1B[1;32m"

char *format_duration(unsigned long micros, char *buf);

int url_encode_component(const void *in, size_t size_in, char *out, size_t size_out);

int url_encode(const void *in, size_t size_in, char *out, size_t size_out);

int url_decode(const char *str, char *dec, long *size);

int mime_is_compressible(const char *type);

int strcpy_rem_webroot(char *dst, const char *str, long len, const char *webroot);

int str_trim(char **start, char **end);

int str_trim_lws(char **start, char **end);

int base64_encode(void *data, unsigned long data_len, char *output, unsigned long *output_len);

long clock_micros(void);

long clock_cpu(void);

#endif //SESIMOS_UTILS_H
