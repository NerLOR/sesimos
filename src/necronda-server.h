/**
 * Necronda Web Server
 * Main executable (header file)
 * src/necronda-server.c
 * Lorenz Stechauner, 2020-12-03
 */

#ifndef NECRONDA_SERVER_NECRONDA_SERVER_H
#define NECRONDA_SERVER_NECRONDA_SERVER_H

#include <sys/types.h>


#define NUM_SOCKETS 4
#define MAX_CHILDREN 1024
#define LISTEN_BACKLOG 16

#define ERR_STR "\x1B[1;31m"
#define CLR_STR "\x1B[0m"

int SOCKETS[NUM_SOCKETS];
pid_t CHILDREN[MAX_CHILDREN];


#endif //NECRONDA_SERVER_NECRONDA_SERVER_H
