/**
 * sesimos - secure, simple, modern web server
 * @brief Error interface
 * @file src/lib/error.c
 * @author Lorenz Stechauner
 * @date 2023-01-08
 */

#include "error.h"
#include "../logger.h"

#include <errno.h>
#include <string.h>

extern const char *sock_error_str(unsigned long err);
extern const char *http_error_str(int err);
extern const char *MMDB_strerror(int err);
extern const char *ERR_reason_error_string(unsigned long err);

static int error_compress(unsigned long err) {
    int comp = ((int) err & 0xFFFF) | (((int) err >> 8) & 0xFF0000);
    if (err & 0xFF0000) warning("Lossy error code compression! (%08lX -> %08X)", err, comp);
    return comp;
}

static unsigned long error_decompress(int err) {
    return (err & 0xFFFF) | ((err << 8) & 0xFF000000);
}

const char *error_str(int err_no, char *buf, int buf_len) {
    buf[0] = 0;
    unsigned char mode = (unsigned char) (err_no >> 24);
    int e = err_no & 0x00FFFFFF;
    if (mode == 0x00) {
        // normal
        return strerror_r(e, buf, buf_len);
    } else if (mode == 0x01) {
        // ssl
        return sock_error_str(error_decompress(e));
    } else if (mode == 0x02) {
        // ssl err
        return ERR_reason_error_string(error_decompress(e));
    } else if (mode == 0x03) {
        // mmdb
        return MMDB_strerror(e);
    } else if (mode == 0x04) {
        // http
        return http_error_str(e);
    }
    return buf;
}

void error_ssl(unsigned long err) {
    errno = 0x01000000 | error_compress(err);
}

void error_ssl_err(unsigned long err) {
    errno = 0x02000000 | error_compress(err);
}

void error_mmdb(int err) {
    errno = 0x03000000 | err;
}

void error_http(int err) {
    errno = 0x04000000 | err;
}

static int error_get(unsigned char prefix) {
    return (errno >> 24 != prefix) ? 0 : errno & 0x00FFFFFF;
}

int error_get_sys() {
    return error_get(0x00);
}

int error_get_ssl() {
    return error_get(0x01);
}

int error_get_ssl_err() {
    return error_get(0x02);
}

int error_get_mmdb() {
    return error_get(0x03);
}

int error_get_http() {
    return error_get(0x04);
}
