//
// Created by lorenz on 5/30/18.
//

#include "procopen.h"

stds procopen(const char* command) {

    int pipes[3][2];

    pipe(pipes[PARENT_READ_PIPE]);
    pipe(pipes[PARENT_WRITE_PIPE]);
    pipe(pipes[PARENT_ERROR_PIPE]);

    int pid = fork();

    if(pid == 0) {
        dup2(CHILD_READ_FD, STDIN_FILENO);
        dup2(CHILD_WRITE_FD, STDOUT_FILENO);
        dup2(CHILD_ERROR_FD, STDERR_FILENO);

        close(CHILD_READ_FD);
        close(CHILD_WRITE_FD);
        close(CHILD_ERROR_FD);

        close(PARENT_READ_FD);
        close(PARENT_WRITE_FD);
        close(PARENT_ERROR_FD);

        system(command);
        exit(0);
    } else {
        close(CHILD_READ_FD);
        close(CHILD_WRITE_FD);
        close(CHILD_ERROR_FD);

        return stds{fdopen(PARENT_WRITE_FD, "w"), fdopen(PARENT_READ_FD, "r"), fdopen(PARENT_ERROR_FD, "r"), (pid_t) pid};
    }
}


