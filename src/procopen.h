//
// Created by lorenz on 5/30/18.
//


#include <zconf.h>
#include <cstdlib>
#include <cstdio>

#ifndef NECRONDA_PROCOPEN
#define NECRONDA_PROCOPEN


#define PARENT_WRITE_PIPE  0
#define PARENT_READ_PIPE   1
#define PARENT_ERROR_PIPE  2

#define READ_FD  0
#define WRITE_FD 1

#define PARENT_READ_FD  ( pipes[PARENT_READ_PIPE][READ_FD]   )
#define PARENT_WRITE_FD ( pipes[PARENT_WRITE_PIPE][WRITE_FD] )
#define PARENT_ERROR_FD ( pipes[PARENT_ERROR_PIPE][READ_FD] )

#define CHILD_READ_FD   ( pipes[PARENT_WRITE_PIPE][READ_FD]  )
#define CHILD_WRITE_FD  ( pipes[PARENT_READ_PIPE][WRITE_FD]  )
#define CHILD_ERROR_FD  ( pipes[PARENT_ERROR_PIPE][WRITE_FD]  )


typedef struct {
    FILE* stdin;
    FILE* stdout;
    FILE* stderr;
    pid_t pid;
} stds;


stds procopen(const char* command);


#endif
