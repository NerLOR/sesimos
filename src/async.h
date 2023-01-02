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

#include <poll.h>

#define ASYNC_KEEP 1

int async(sock *s, short events, int flags, void cb(void *), void *arg, void err_cb(void *), void *err_arg);

int async_fd(int fd, short events, int flags, void cb(void *), void *arg, void err_cb(void *), void *err_arg);

int async_init(void);

void async_free(void);

void async_thread(void);

void async_stop(void);

#endif //SESIMOS_ASYNC_H
