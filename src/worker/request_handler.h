/**
 * sesimos - secure, simple, modern web server
 * @brief Client request handler (header file)
 * @file src/worker/request_handler.h
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#ifndef SESIMOS_REQUEST_HANDLER_H
#define SESIMOS_REQUEST_HANDLER_H

#include "../server.h"

int request_handler_init(int n_workers, int buf_size);

int handle_request(client_ctx_t *ctx);

void request_handler_stop(void);

void request_handler_destroy(void);

#endif //SESIMOS_REQUEST_HANDLER_H
