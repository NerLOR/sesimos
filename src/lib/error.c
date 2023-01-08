/**
 * sesimos - secure, simple, modern web server
 * @brief Error interface
 * @file src/lib/error.c
 * @author Lorenz Stechauner
 * @date 2023-01-08
 */

#include "error.h"
#include "http.h"

#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <maxminddb.h>

static const char *error_ssl_strerror(int err) {
    switch (err) {
        case SSL_ERROR_ZERO_RETURN:
            return "closed";
        case SSL_ERROR_WANT_READ:
            return "want read";
        case SSL_ERROR_WANT_WRITE:
            return "want write";
        case SSL_ERROR_WANT_CONNECT:
            return "want connect";
        case SSL_ERROR_WANT_ACCEPT:
            return "want accept";
        case SSL_ERROR_WANT_X509_LOOKUP:
            return "want x509 lookup";
        case SSL_ERROR_WANT_ASYNC:
            return "want async";
        case SSL_ERROR_WANT_ASYNC_JOB:
            return "want async job";
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            return "want client hello callback";
        case SSL_ERROR_WANT_RETRY_VERIFY:
            return "want retry verify";
        case SSL_ERROR_SSL:
            return ERR_reason_error_string(ERR_get_error());
        default:
            return "unknown error";
    }
}

static const char *error_http_strerror(int err) {
    switch (err) {
        default:
            return "unknown error";
    }
}

const char *error_str(int err_no, char *buf, int buf_len) {
    buf[0] = 0;
    unsigned char mode = (unsigned char) (err_no >> 24);
    int e = err_no & 0x00FFFFFF;
    if (mode == 0x00) {
        // normal
        strerror_r(e, buf, buf_len);
        return buf;
    } else if (mode == 0x01) {
        // ssl
        return error_ssl_strerror(e);
    } else if (mode == 0x02) {
        // mmdb
        return MMDB_strerror(e);
    } else if (mode == 0x03) {
        // http
        return error_http_strerror(e);
    }
    return buf;
}

void error_ssl(int err) {
    if (err == SSL_ERROR_NONE) {
        errno = 0;
    } else if (err == SSL_ERROR_SYSCALL) {
        // errno already set
    } else {
        errno = 0x01000000 | err;
    }
}

void error_mmdb(int err) {
    if (err == MMDB_SUCCESS) {
        errno = 0;
    } else if (err == MMDB_IO_ERROR) {
        // errno already set
    } else {
        errno = 0x02000000 | err;
    }
}

int error_http(int err) {
    if (err == 0) {
        errno = 0;
    } else if (err == HTTP_ERROR_SYSCALL) {
        // errno already set
    } else {
        errno = 0x03000000 | err;
    }
    return -1;
}
