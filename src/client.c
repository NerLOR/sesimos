/**
 * Necronda Web Server
 * Client connection and request handlers
 * src/client.c
 * Lorenz Stechauner, 2020-12-03
 */

#include <sys/types.h>
#include <unistd.h>

#include "necronda-server.h"
#include "utils.h"
#include "net/http.h"


int client_websocket_handler() {
    // TODO implement client_websocket_handler
    return 0;
}

int client_request_handler() {
    // TODO implement client_request_handler
    return 0;
}

int client_connection_handler() {
    // TODO implement client_connection_handler
    return 0;
}

pid_t client_handler(int socket) {
    struct sockaddr_in client_addr;
    unsigned int client_addr_len = sizeof(client_addr);

    int client = accept(socket, (struct sockaddr *) &client_addr, &client_addr_len);
    if (client == -1) {
        fprintf(stderr, ERR_STR "Unable to accept connection: %s" CLR_STR "\n", strerror(errno));
        return -1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // child
        recv(client, NULL, 0, 0);
        char buf[] = "Hello world!\n";
        send(client, buf, strlen(buf), 0);
        close(client);
        return 0;
    } else {
        // parent
        close(client);
        return pid;
    }
}
