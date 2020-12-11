/**
 * Necronda Web Server
 * HTTP implementation
 * src/net/http.c
 * Lorenz Stechauner, 2020-12-09
 */

#include "http.h"
#include "utils.h"


int http_receive_request(sock *client, http_req *req) {
    char *buf = malloc(CLIENT_MAX_HEADER_SIZE);
    ssize_t len;
    memset(buf, 0, CLIENT_MAX_HEADER_SIZE);

    while (1) {
        if (client->enc) {
            len = SSL_read(client->ssl, buf, CLIENT_MAX_HEADER_SIZE);
            if (len < 0) {
                print(ERR_STR "Unable to receive: %s" CLR_STR, ssl_get_error(client->ssl, len));
                continue;
            }
        } else {
            len = recv(client->socket, buf, CLIENT_MAX_HEADER_SIZE, 0);
            if (len < 0) {
                print(ERR_STR "Unable to receive: %s" CLR_STR, strerror(errno));
                continue;
            }
        }
        break;
    }

    return 0;
}
