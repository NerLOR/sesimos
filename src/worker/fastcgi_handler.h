/**
 * sesimos - secure, simple, modern web server
 * @brief TCP closer (header file)
 * @file src/worker/fastcgi_handler.h
 * @author Lorenz Stechauner
 * @date 2022-12-29
 */

#ifndef SESIMOS_FASTCGI_HANDLER_H
#define SESIMOS_FASTCGI_HANDLER_H

#include "../server.h"

void fastcgi_handler_func(client_ctx_t *ctx);

#endif //SESIMOS_FASTCGI_HANDLER_H
