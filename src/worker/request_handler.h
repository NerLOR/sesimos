
#ifndef SESIMOS_REQUEST_HANDLER_H
#define SESIMOS_REQUEST_HANDLER_H

#include "../client.h"

int request_handler_init(int n_workers, int buf_size);

int handle_request(client_ctx_t *ctx);

void request_handler_stop(void);

void request_handler_destroy(void);

#endif //SESIMOS_REQUEST_HANDLER_H
