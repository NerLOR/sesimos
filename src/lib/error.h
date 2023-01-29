/**
 * sesimos - secure, simple, modern web server
 * @brief Error interface (header fie)
 * @file src/lib/error.h
 * @author Lorenz Stechauner
 * @date 2023-01-08
 */

#ifndef SESIMOS_ERROR_H
#define SESIMOS_ERROR_H

const char *error_str(int err_no, char *buf, int buf_len);

void error_ssl(unsigned long err);

void error_ssl_err(unsigned long err);

void error_mmdb(int err);

void error_http(int err);

void error_gai(int err);

int error_get_sys();

int error_get_ssl();

int error_get_mmdb();

int error_get_http();

#endif //SESIMOS_ERROR_H
