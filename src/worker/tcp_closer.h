
#ifndef SESIMOS_TCP_CLOSER_H
#define SESIMOS_TCP_CLOSER_H

#include "../client.h"

int tcp_closer_init(int n_workers, int buf_size);

int tcp_close(client_ctx_t *ctx);

void tcp_closer_stop(void);

void tcp_closer_destroy(void);

#endif //SESIMOS_TCP_CLOSER_H
