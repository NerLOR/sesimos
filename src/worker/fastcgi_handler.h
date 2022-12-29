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

int fastcgi_handler_init(int n_workers, int buf_size);

int fastcgi_handle(client_ctx_t *ctx);

void fastcgi_handler_stop(void);

void fastcgi_handler_destroy(void);

#endif //SESIMOS_FASTCGI_HANDLER_H
