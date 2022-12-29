/**
 * sesimos - secure, simple, modern web server
 * @brief HTTP responder (header file)
 * @file src/worker/responderr.h
 * @author Lorenz Stechauner
 * @date 2022-12-29
 */

#ifndef SESIMOS_RESPONDER_H
#define SESIMOS_RESPONDER_H

#include "../server.h"

void responder_func(client_ctx_t *ctx);

#endif //SESIMOS_RESPONDER_H
