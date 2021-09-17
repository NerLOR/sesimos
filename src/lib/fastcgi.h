/**
 * Necronda Web Server
 * FastCGI interface implementation (header file)
 * src/lib/fastcgi.h
 * Lorenz Stechauner, 2020-12-26
 */

#ifndef NECRONDA_SERVER_FASTCGI_H
#define NECRONDA_SERVER_FASTCGI_H

#include "include/fastcgi.h"
#include "http.h"
#include "uri.h"

#define FASTCGI_CHUNKED 1
#define FASTCGI_COMPRESS_GZ 2
#define FASTCGI_COMPRESS_BR 4
#define FASTCGI_COMPRESS 6

#define FASTCGI_PHP 1
#define FASTCGI_NECRONDA 2

#ifndef PHP_FPM_SOCKET
#   define PHP_FPM_SOCKET "/var/run/php-fpm/php-fpm.sock"
#endif

#define NECRONDA_BACKEND_SOCKET "/var/run/necronda/necronda-backend.sock"

typedef struct {
    int mode;
    int socket;
    unsigned short req_id;
    char *out_buf;
    unsigned short out_len;
    unsigned short out_off;
} fastcgi_conn;

char *fastcgi_add_param(char *buf, const char *key, const char *value);

int fastcgi_init(fastcgi_conn *conn, int mode, unsigned int client_num, unsigned int req_num, const sock *client,
                 const http_req *req, const http_uri *uri);

int fastcgi_close_stdin(fastcgi_conn *conn);

int fastcgi_php_error(const char *msg, int msg_len, char *err_msg);

int fastcgi_header(fastcgi_conn *conn, http_res *res, char *err_msg);

int fastcgi_send(fastcgi_conn *conn, sock *client, int flags);

int fastcgi_receive(fastcgi_conn *conn, sock *client, unsigned long len);

#endif //NECRONDA_SERVER_FASTCGI_H
