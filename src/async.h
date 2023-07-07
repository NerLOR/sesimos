/**
 * Sesimos - secure, simple, modern web server
 * @brief Async handler (header file)
 * @file src/async.h
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#ifndef SESIMOS_ASYNC_H
#define SESIMOS_ASYNC_H

#include "lib/sock.h"

#define ASYNC_KEEP 1
#define ASYNC_IGNORE_PENDING 2

#define ASYNC_IN   0x01
#define ASYNC_PRI  0x02
#define ASYNC_OUT  0x04
#define ASYNC_ERR  0x08
#define ASYNC_HUP  0x10

#define ASYNC_WAIT_READ  ASYNC_IN
#define ASYNC_WAIT_WRITE ASYNC_OUT

typedef unsigned int async_evt_t;

int async(sock *s, async_evt_t events, int flags, void *arg, void cb(void *), void to_cb(void *), void err_cb(void *));

int async_fd(int fd, async_evt_t events, int flags, void *arg, void cb(void *), void to_cb(void *), void err_cb(void *));

int async_init(void);

void async_free(void);

void async_thread(void);

void async_stop(void);

#endif //SESIMOS_ASYNC_H
