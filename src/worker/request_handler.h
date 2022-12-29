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

void request_handler_func(client_ctx_t *ctx);

#endif //SESIMOS_REQUEST_HANDLER_H
