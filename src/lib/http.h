/**
 * sesimos - secure, simple, modern web server
 * @brief HTTP implementation (header file)
 * @file src/lib/http.h
 * @author Lorenz Stechauner
 * @date 2020-12-09
 */

#ifndef SESIMOS_HTTP_H
#define SESIMOS_HTTP_H

#include "sock.h"

#define HTTP_PRESERVE 0
#define HTTP_LOWER 1
#define HTTP_CAMEL 2

#define HTTP_REMOVE_ONE 0
#define HTTP_REMOVE_ALL 1
#define HTTP_REMOVE_LAST 2

#define HTTP_FIELD_NORMAL 0
#define HTTP_FIELD_EX_VALUE 1
#define HTTP_FIELD_EX_NAME 2

#define HTTP_MERGE_FIELDS 1

#define HTTP_1XX_STR "\x1B[1;32m"
#define HTTP_2XX_STR "\x1B[1;32m"
#define HTTP_3XX_STR "\x1B[1;33m"
#define HTTP_4XX_STR "\x1B[1;31m"
#define HTTP_5XX_STR "\x1B[1;31m"

#define HTTP_COLOR_SUCCESS "#008000"
#define HTTP_COLOR_INFO    "#606060"
#define HTTP_COLOR_WARNING "#E0C000"
#define HTTP_COLOR_ERROR   "#C00000"

#define CLIENT_MAX_HEADER_SIZE 8192
#define HTTP_INIT_HEADER_FIELD_NUM 16

#define HTTP_TYPE_INFORMATIONAL 1
#define HTTP_TYPE_SUCCESS       2
#define HTTP_TYPE_REDIRECTION   3
#define HTTP_TYPE_CLIENT_ERROR  4
#define HTTP_TYPE_SERVER_ERROR  5

#define HTTP_ERROR_GENERAL 1
#define HTTP_ERROR_SYSCALL 2
#define HTTP_ERROR_TOO_MANY_HEADER_FIELDS 3
#define HTTP_ERROR_EOH_NOT_FOUND 4
#define HTTP_ERROR_HEADER_MALFORMED 5
#define HTTP_ERROR_INVALID_VERSION 6
#define HTTP_ERROR_URI_TOO_LONG 7
#define HTTP_ERROR_

#ifndef SERVER_STR
#   define SERVER_STR "sesimos"
#endif

#ifndef SERVER_STR_HTML
#   define SERVER_STR_HTML "sesimos&nbsp;web&nbsp;server"
#endif

typedef struct {
    unsigned short code:10;
    unsigned char type:3;
    char msg[64];
} http_status;

typedef struct {
    unsigned short code:10;
    const char *msg;
} http_status_msg;

typedef struct {
    char mode[8];
    char color[8];
    const char *icon;
    const char *doc;
} http_doc_info;

typedef struct {
    char type;
    union {
        struct {
            char name[32];
            char value[32];
        } normal;
        struct {
            char name[64 - sizeof(char *)];
            char *value;
        } ex_value;
        struct {
            char *name;
            char *value;
        } ex_name;
    };
} http_field;

typedef struct {
    int last_field_num;
    http_field *fields;
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
    const char* ws_key;
} http_status_ctx;

extern const http_status http_statuses[];
extern const http_status_msg http_status_messages[];
extern const int http_statuses_size;
extern const int http_status_messages_size;

extern const char http_error_doc[], http_warning_doc[], http_success_doc[], http_info_doc[];

void http_to_camel_case(char *str, int mode);

const char *http_field_get_name(const http_field *field);

const char *http_field_get_value(const http_field *field);

int http_init_hdr(http_hdr *hdr);

void http_free_field(http_field *f);

void http_free_hdr(http_hdr *hdr);

void http_free_req(http_req *req);

void http_free_res(http_res *res);

int http_parse_request(char *buf, http_req *req);

int http_receive_request(sock *client, http_req *req);

int http_parse_header_field(http_hdr *hdr, const char *buf, const char *end_ptr, int flags);

const char *http_get_header_field(const http_hdr *hdr, const char *field_name);

const char *http_get_header_field_len(const http_hdr *hdr, const char *field_name, unsigned long len);

int http_get_header_field_num(const http_hdr *hdr, const char *field_name);

int http_get_header_field_num_len(const http_hdr *hdr, const char *field_name, unsigned long len);

int http_add_header_field(http_hdr *hdr, const char *field_name, const char *field_value);

int http_add_header_field_len(http_hdr *hdr, const char *name, unsigned long name_len, const char *value, unsigned long value_len);

void http_append_to_header_field(http_field *field, const char *value, unsigned long len);

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

#endif //SESIMOS_HTTP_H
