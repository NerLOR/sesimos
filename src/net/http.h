/**
 * Necronda Web Server
 * HTTP implementation (header file)
 * src/net/http.h
 * Lorenz Stechauner, 2020-12-09
 */

#ifndef NECRONDA_SERVER_HTTP_H
#define NECRONDA_SERVER_HTTP_H

typedef struct {
    unsigned short code;
    char type[16];
    char msg[32];
} http_status;

typedef struct {
    char field_num;
    char *fields[64][2];
} http_hdr;

typedef struct {
    char method[8];
    char *uri;
    char version[3];
    http_hdr hdr;
} http_req;

typedef struct {
    http_status *status;
    char version[3];
    http_hdr hdr;
} http_res;

http_status http_statuses[] = {
        {100, "Informational", "Continue"},
        {101, "Informational", "Switching Protocols"},

        {200, "Success",       "OK"},
        {201, "Success",       "Created"},
        {202, "Success",       "Accepted"},
        {203, "Success",       "Non-Authoritative Information"},
        {204, "Success",       "No Content"},
        {205, "Success",       "Reset Content"},
        {206, "Success",       "Partial Content"},

        {300, "Redirection",   "Multiple Choices"},
        {301, "Redirection",   "Moved Permanently"},
        {302, "Redirection",   "Found"},
        {303, "Redirection",   "See Other"},
        {304, "Redirection",   "Not Modified"},
        {305, "Redirection",   "Use Proxy"},
        {307, "Redirection",   "Temporary Redirect"},
        {308, "Redirection",   "Permanent Redirect"},

        {400, "Client Error",  "Bad Request"},
        {401, "Client Error",  "Unauthorized"},
        {402, "Client Error",  "Payment Required"},
        {403, "Client Error",  "Forbidden"},
        {404, "Client Error",  "Not Found"},
        {405, "Client Error",  "Method Not Allowed"},
        {406, "Client Error",  "Not Acceptable"},
        {407, "Client Error",  "Proxy Authentication Required"},
        {408, "Client Error",  "Request Timeout"},
        {409, "Client Error",  "Conflict"},
        {410, "Client Error",  "Gone"},
        {411, "Client Error",  "Length Required"},
        {412, "Client Error",  "Precondition Failed"},
        {413, "Client Error",  "Request Entity Too Large"},
        {414, "Client Error",  "Request-URI Too Long"},
        {415, "Client Error",  "Unsupported Media Type"},
        {416, "Client Error",  "Requested Range Not Satisfiable"},
        {417, "Client Error",  "Expectation Failed"},

        {500, "Server Error",  "Internal Server Error"},
        {501, "Server Error",  "Not Implemented"},
        {502, "Server Error",  "Bad Gateway"},
        {503, "Server Error",  "Service Unavailable"},
        {504, "Server Error",  "Gateway Timeout"},
        {505, "Server Error",  "HTTP Version Not Supported"},
};


void http_to_camel_case(char *str);

void http_free_hdr(http_hdr *hdr);

void http_free_req(http_req *req);

void http_free_res(http_res *res);

int http_receive_request(sock *client, http_req *req);

char *http_get_header_field(http_hdr *hdr, char *field_name);

void http_add_header_field(http_hdr *hdr, char *field_name, char *field_value);

int http_send_response(sock *client, http_res *res);

const char *http_get_status_color(http_status *status);

char *http_format_date(time_t time, char *buf, size_t size);

char *http_get_date(char *buf, size_t size);

#endif //NECRONDA_SERVER_HTTP_H
