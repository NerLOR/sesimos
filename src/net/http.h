/**
 * Necronda Web Server
 * HTTP implementation (header file)
 * src/net/http.h
 * Lorenz Stechauner, 2020-12-09
 */

#ifndef NECRONDA_SERVER_HTTP_H
#define NECRONDA_SERVER_HTTP_H

typedef struct {
    char method[8];
    char *uri;
    char version[3];
    char field_num;
    char *fields[64][2];
} http_req;

int http_receive_request(sock *client, http_req *req);

#endif //NECRONDA_SERVER_HTTP_H
