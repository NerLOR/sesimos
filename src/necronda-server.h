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


#define NUM_SOCKETS 2
#define MAX_CHILDREN 1024
#define LISTEN_BACKLOG 16

#define ERR_STR "\x1B[1;31m"
#define CLR_STR "\x1B[0m"
#define R_STR "\x1B[31m"
#define G_STR "\x1B[32m"

int SOCKETS[NUM_SOCKETS];
pid_t CHILDREN[MAX_CHILDREN];

FILE *parent_stdout, *parent_stderr;


#endif //NECRONDA_SERVER_NECRONDA_SERVER_H
