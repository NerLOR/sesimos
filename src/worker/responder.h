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

int responder_init(int n_workers, int buf_size);

int respond(client_ctx_t *ctx);

void responder_stop(void);

void responder_destroy(void);

#endif //SESIMOS_RESPONDER_H
