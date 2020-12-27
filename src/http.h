/**
 * Necronda Web Server
 * HTTP implementation (header file)
 * src/net/http.h
 * Lorenz Stechauner, 2020-12-09
 */

#ifndef NECRONDA_SERVER_HTTP_H
#define NECRONDA_SERVER_HTTP_H

#define HTTP_LOWER 1
#define HTTP_PRESERVE_UPPER 0

typedef struct {
    unsigned short code;
    char type[16];
    char msg[32];
} http_status;

typedef struct {
    unsigned short code;
    char *err_msg;
} http_error_msg;

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

http_error_msg http_error_messages[] = {
        {400, "The request could not be understood by the server due to malformed syntax."},
        {401, "The request requires user authentication."},
        {403, "The server understood the request, but is refusing to fulfill it."},
        {404, "The server has not found anything matching the Request-URI."},
        {405, "The method specified in the Request-Line is not allowed for the resource identified by the Request-URI."},
        {406, "The resource identified by the request is only capable of generating response entities which have content characteristics not acceptable according to the accept headers sent in the request."},
        {407, "The request requires user authentication on the proxy."},
        {408, "The client did not produce a request within the time that the server was prepared to wait."},
        {409, "The request could not be completed due to a conflict with the current state of the resource."},
        {410, "The requested resource is no longer available at the server and no forwarding address is known."},
        {411, "The server refuses to accept the request without a defined Content-Length."},
        {412, "The precondition given in one or more of the request-header fields evaluated to false when it was tested on the server."},
        {413, "The server is refusing to process a request because the request entity is larger than the server is willing or able to process."},
        {414, "The server is refusing to service the request because the Request-URI is longer than the server is willing to interpret."},
        {415, "The server is refusing to service the request because the entity of the request is in a format not supported by the requested resource for the requested method."},
        {417, "The expectation given in an Expect request-header field could not be met by this server, or, if the server is a proxy, the server has unambiguous evidence that the request could not be met by the next-hop server."},

        {500, "The server encountered an unexpected condition which prevented it from fulfilling the request."},
        {501, "The server does not support the functionality required to fulfill the request."},
        {502, "The server, while acting as a gateway or proxy, received an invalid response from the upstream server it accessed in attempting to fulfill the request."},
        {503, "The server is currently unable to handle the request due to a temporary overloading or maintenance of the server."},
        {504, "The server, while acting as a gateway or proxy, did not receive a timely response from the upstream server specified by the URI or some other auxiliary server it needed to access in attempting to complete the request."},
        {505, "The server does not support, or refuses to support, the HTTP protocol version that was used in the request message."}
};

const char *http_default_document =
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "    <title>%1$i %2$s</title>\n"
        "    <meta charset=\"UTF-8\"/>\n"
        "    <meta name=\"theme-color\" content=\"%6$s\"/>\n"
        "    <meta name=\"apple-mobile-web-app-status-bar-style\" content=\"black-translucent\"/>\n"
        "    <meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\"/>\n"
        "%5$s"
        "    <style>\n"
        "        html{font-family:\"Arial\",sans-serif;--error:#C00000;--info:#E0C000;--color:var(--%4$s);}\n"
        "        body{background-color:#F0F0F0;margin:0.5em;}\n"
        "        main{max-width:600px;margin:2em auto;background-color:#FFFFFF;border: 1px solid var(--color);border-radius:4px;padding:1em 2em;}\n"
        "        h1,h2,h3,h4,h5,h6,h7{text-align:center;color:var(--color);}\n"
        "        h1{margin:0.5em 0;font-size:1.5em;}\n"
        "        p{text-align:center;}\n"
        "        div.footer{color:#808080;font-size:0.75em;text-align:center;margin:0.5em 0;}\n"
        "    </style>\n"
        "</head>\n"
        "<body>\n"
        "    <main>\n"
        "%3$s"
        "        <div class=\"footer\">Necronda web server " NECRONDA_VERSION "</div>\n"
        "    </main>\n"
        "</body>\n"
        "</html>\n";

const char *http_error_document =
        "        <h1>%1$i %2$s :&#xFEFF;(</h1>\n"
        "        <p>%3$s</p>\n"
        "        <p>%4$s</p>\n";

const char *http_error_icon =
        "    <link rel=\"shortcut icon\" type=\"image/svg+xml\" sizes=\"any\" href=\"data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHRleHQgeD0iNCIgeT0iMTIiIGZpbGw9IiNDMDAwMDAiIHN0eWxlPSJmb250LWZhbWls"
        "eTonQXJpYWwnLHNhbnMtc2VyaWYiPjooPC90ZXh0Pjwvc3ZnPgo=\"/>\n";


void http_to_camel_case(char *str, int strict);

void http_free_hdr(http_hdr *hdr);

void http_free_req(http_req *req);

void http_free_res(http_res *res);

int http_receive_request(sock *client, http_req *req);

char *http_get_header_field(const http_hdr *hdr, const char *field_name, int strict);

void http_add_header_field(http_hdr *hdr, const char *field_name, const char *field_value);

int http_send_response(sock *client, http_res *res);

http_status *http_get_status(unsigned short status_code);

http_error_msg *http_get_error_msg(unsigned short status_code);

const char *http_get_status_color(http_status *status);

char *http_format_date(time_t time, char *buf, size_t size);

char *http_get_date(char *buf, size_t size);

#endif //NECRONDA_SERVER_HTTP_H
