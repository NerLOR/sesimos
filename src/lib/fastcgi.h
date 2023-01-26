/**
 * sesimos - secure, simple, modern web server
 * @brief FastCGI interface implementation (header file)
 * @file src/lib/fastcgi.h
 * @author Lorenz Stechauner
 * @date 2020-12-26
 */

#ifndef SESIMOS_FASTCGI_H
#define SESIMOS_FASTCGI_H

#include "include/fastcgi.h"
#include "http.h"
#include "uri.h"

#define FASTCGI_TIMEOUT 3600

#define FASTCGI_BACKEND_PHP 1

#ifndef PHP_FPM_SOCKET
#   define PHP_FPM_SOCKET "/var/run/php-fpm/php-fpm.sock"
#endif

typedef struct {
    int mode;
    sock socket, out;
    int fd_err, fd_out;
    FILE *err;
    unsigned short req_id;
    int app_status;
    const char *webroot;
    char *r_addr;
    char *r_host;
} fastcgi_cnx_t;

char *fastcgi_add_param(char *buf, const char *key, const char *value);

int fastcgi_init(fastcgi_cnx_t *conn, int mode, unsigned int req_num, const sock *client, const http_req *req, const http_uri *uri);

int fastcgi_close_cnx(fastcgi_cnx_t *cnx);

int fastcgi_close_stdin(fastcgi_cnx_t *conn);

int fastcgi_php_error(const fastcgi_cnx_t *conn, const char *msg, int msg_len, char *err_msg);

int fastcgi_recv_frame(fastcgi_cnx_t *cnx);

int fastcgi_header(fastcgi_cnx_t *cnx, http_res *res, char *err_msg);

long fastcgi_send(fastcgi_cnx_t *cnx, sock *client);

int fastcgi_dump(fastcgi_cnx_t *cnx, char *buf, long len);

int fastcgi_receive(fastcgi_cnx_t *cnx, sock *client, unsigned long len);

int fastcgi_receive_chunked(fastcgi_cnx_t *cnx, sock *client);



#endif //SESIMOS_FASTCGI_H
