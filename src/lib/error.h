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

void error_ssl(int err);

void error_mmdb(int err);

int error_http(int err);

#endif //SESIMOS_ERROR_H
