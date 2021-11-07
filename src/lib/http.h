/**
 * Necronda Web Server
 * HTTP implementation (header file)
 * src/lib/http.h
 * Lorenz Stechauner, 2020-12-09
 */

#ifndef NECRONDA_SERVER_HTTP_H
#define NECRONDA_SERVER_HTTP_H

#include "sock.h"

#define HTTP_PRESERVE 0
#define HTTP_LOWER 1
#define HTTP_CAMEL 2

#define HTTP_REMOVE_ONE 0
#define HTTP_REMOVE_ALL 1
#define HTTP_REMOVE_LAST 2

#define HTTP_1XX_STR "\x1B[1;32m"
#define HTTP_2XX_STR "\x1B[1;32m"
#define HTTP_3XX_STR "\x1B[1;33m"
#define HTTP_4XX_STR "\x1B[1;31m"
#define HTTP_5XX_STR "\x1B[1;31m"

#define HTTP_COLOR_SUCCESS "#008000"
#define HTTP_COLOR_INFO "#606060"
#define HTTP_COLOR_WARNING "#E0C000"
#define HTTP_COLOR_ERROR "#C00000"

#define CLIENT_MAX_HEADER_SIZE 8192

#ifndef SERVER_STR
#   define SERVER_STR "Necronda"
#endif

#ifndef SERVER_STR_HTML
#   define SERVER_STR_HTML "Necronda&nbsp;web&nbsp;server"
#endif

typedef struct {
    unsigned short code;
    char type[16];
    char msg[64];
} http_status;

typedef struct {
    unsigned short code;
    const char *msg;
} http_status_msg;

typedef struct {
    char mode[8];
    char color[8];
    const char *icon;
    const char *doc;
} http_doc_info;

typedef struct {
    char field_num;
    char *fields[64][2];
} http_hdr;

typedef struct {
    char method[16];
    char *uri;
    char version[4];
    http_hdr hdr;
} http_req;

typedef struct {
    const http_status *status;
    char version[4];
    http_hdr hdr;
} http_res;

typedef enum {
    NONE, INTERNAL, CLIENT_REQ, SERVER_REQ, SERVER, SERVER_RES, CLIENT_RES
} http_error_origin;

typedef struct {
    unsigned short status;
    http_error_origin origin;
} http_status_ctx;

extern const http_status http_statuses[];
extern const http_status_msg http_status_messages[];
extern const int http_statuses_size;
extern const int http_status_messages_size;

extern const char http_default_document[];
extern const char http_rev_proxy_document[];
extern const char http_error_document[];
extern const char http_error_icon[];
extern const char http_warning_document[];
extern const char http_warning_icon[];
extern const char http_success_document[];
extern const char http_success_icon[];
extern const char http_info_document[];
extern const char http_info_icon[];

void http_to_camel_case(char *str, int mode);

void http_free_hdr(http_hdr *hdr);

void http_free_req(http_req *req);

void http_free_res(http_res *res);

int http_receive_request(sock *client, http_req *req);

int http_parse_header_field(http_hdr *hdr, const char *buf, const char *end_ptr) ;

char *http_get_header_field(const http_hdr *hdr, const char *field_name);

void http_add_header_field(http_hdr *hdr, const char *field_name, const char *field_value);

void http_remove_header_field(http_hdr *hdr, const char *field_name, int mode);

int http_send_response(sock *client, http_res *res);

int http_send_request(sock *server, http_req *req);

const http_status *http_get_status(unsigned short status_code);

const http_status_msg *http_get_error_msg(const http_status *status);

const char *http_get_status_color(const http_status *status);

char *http_format_date(time_t time, char *buf, size_t size);

char *http_get_date(char *buf, size_t size);

const http_doc_info *http_get_status_info(const http_status *status);

int http_get_compression(const http_req *req, const http_res *res);

#endif //NECRONDA_SERVER_HTTP_H
