/**
 * Necronda Web Server
 * Main executable (header file)
 * src/necronda-server.c
 * Lorenz Stechauner, 2020-12-03
 */

#ifndef NECRONDA_SERVER_NECRONDA_SERVER_H
#define NECRONDA_SERVER_NECRONDA_SERVER_H

#include <sys/types.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/dh.h>


#define NUM_SOCKETS 2
#define MAX_CHILDREN 1024
#define LISTEN_BACKLOG 16
#define REQ_PER_CONNECTION 100

#define CLIENT_MAX_HEADER_SIZE 8192

#define ERR_STR "\x1B[1;31m"
#define CLR_STR "\x1B[0m"
#define HTTP_STR "\x1B[1;31m"
#define HTTPS_STR "\x1B[1;32m"

int SOCKETS[NUM_SOCKETS];
pid_t CHILDREN[MAX_CHILDREN];

FILE *parent_stdout, *parent_stderr;

typedef struct {
    int enc:1;
    int socket;
    SSL_CTX *ctx;
    SSL *ssl;
} sock;

char *ssl_get_error(SSL *ssl, int ret);

#endif //NECRONDA_SERVER_NECRONDA_SERVER_H
