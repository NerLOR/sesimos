/**
 * sesimos - secure, simple, modern web server
 * HTTP static implementation
 * src/lib/http_static.c
 * Lorenz Stechauner, 2021-05-03
 */

#include "../defs.h"
#include "http.h"


const http_status http_statuses[] = {
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
        {304, "Success",       "Not Modified"},
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
        {416, "Client Error",  "Range Not Satisfiable"},
        {417, "Client Error",  "Expectation Failed"},

        {500, "Server Error",  "Internal Server Error"},
        {501, "Server Error",  "Not Implemented"},
        {502, "Server Error",  "Bad Gateway"},
        {503, "Server Error",  "Service Unavailable"},
        {504, "Server Error",  "Gateway Timeout"},
        {505, "Server Error",  "HTTP Version Not Supported"},
};

const http_status_msg http_status_messages[] = {
        {100, "The client SHOULD continue with its request."},
        {101, "The server understands and is willing to comply with the clients request, via the Upgrade message header field, for a change in the application protocol being used on this connection."},

        {200, "The request has succeeded."},
        {201, "The request has been fulfilled and resulted in a new resource being created."},
        {202, "The request has been accepted for processing, but the processing has not been completed."},
        {203, "The returned meta information in the entity-header is not the definitive set as available from the origin server, but is gathered from a local or a third-party copy."},
        {204, "The server has fulfilled the request but does not need to return an entity-body, and might want to return updated meta information."},
        {205, "The server has fulfilled the request and the user agent SHOULD reset the document view which caused the request to be sent."},
        {206, "The server has fulfilled the partial GET request for the resource."},

        {300, "The requested resource corresponds to any one of a set of representations, each with its own specific location, and agent-driven negotiation information is being provided so that the user (or user agent) can select a preferred representation and redirect its request to that location."},
        {301, "The requested resource has been assigned a new permanent URI and any future references to this resource SHOULD use one of the returned URIs."},
        {302, "The requested resource resides temporarily under a different URI."},
        {303, "The response to the request can be found under a different URI and SHOULD be retrieved using a GET method on that resource."},
        {304, "The request has been fulfilled and the requested resource has not been modified."},
        {305, "The requested resource MUST be accessed through the proxy given by the Location field."},
        {307, "The requested resource resides temporarily under a different URI."},
        {308, "The requested resource has been assigned a new permanent URI and any future references to this resource ought to use one of the enclosed URIs."},

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
        {416, "None of the ranges in the requests Range header field overlap the current extent of the selected resource or that the set of ranges requested has been rejected due to invalid ranges or an excessive request of small or overlapping ranges."},
        {417, "The expectation given in an Expect request-header field could not be met by this server, or, if the server is a proxy, the server has unambiguous evidence that the request could not be met by the next-hop server."},

        {500, "The server encountered an unexpected condition which prevented it from fulfilling the request."},
        {501, "The server does not support the functionality required to fulfill the request."},
        {502, "The server, while acting as a gateway or proxy, received an invalid response from the upstream server it accessed in attempting to fulfill the request."},
        {503, "The server is currently unable to handle the request due to a temporary overloading or maintenance of the server."},
        {504, "The server, while acting as a gateway or proxy, did not receive a timely response from the upstream server specified by the URI or some other auxiliary server it needed to access in attempting to complete the request."},
        {505, "The server does not support, or refuses to support, the HTTP protocol version that was used in the request message."}
};

const char http_default_document[] =
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "\t<title>%1$i %2$s - %7$s</title>\n"
        "\t<meta charset=\"UTF-8\"/>\n"
        "\t<meta name=\"theme-color\" content=\"%6$s\"/>\n"
        "\t<meta name=\"color-scheme\" content=\"light dark\"/>\n"
        "\t<meta name=\"apple-mobile-web-app-status-bar-style\" content=\"black-translucent\"/>\n"
        "\t<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\"/>\n"
        "\t<link rel=\"shortcut icon\" type=\"image/x-icon\" href=\"/favicon.ico\"/>\n"
        "%5$s"
        "\t<style>\n"
        "\t\thtml{font-family:\"Arial\",sans-serif;--error:" HTTP_COLOR_ERROR ";--warning:" HTTP_COLOR_WARNING ";--success:" HTTP_COLOR_SUCCESS ";--info:" HTTP_COLOR_INFO ";--soft:#808080;--color:var(--%4$s);}\n"
        "\t\tbody{background-color:#F0F0F0;margin:0;}\n"
        "\t\tmain{max-width:650px;margin:2em auto;}\n"
        "\t\tsection{margin:2em 1em;background-color:#FFFFFF;border: 1px solid var(--color);border-radius:4px;padding:1em;}\n"
        "\t\th1,h2,h3,h4,h5,h6{text-align:center;color:var(--color);font-weight:normal;}\n"
        "\t\th1{font-size:3em;margin:0.125em 0;}\n"
        "\t\th2{font-size:1.5em;margin:0.25em 0 1em 0;}\n"
        "\t\tp{text-align:center;font-size:0.875em;}\n"
        "\t\tdiv.footer{color:var(--soft);font-size:0.75em;text-align:center;margin:2em 0 0.5em 0;}\n"
        "\t\tdiv.footer a{color:var(--soft);}\n"
        "\t\tul,ol{width:fit-content;margin:auto;}\n"
        "\t\tpre{width:fit-content;margin:2em auto 0 auto;}\n"
        "\n"
        "\t\tsection.error-ctx{display:flex;padding:0;border:none;}\n"
        "\t\tdiv.box{flex:100%% 1 1;border:1px solid var(--info);color:var(--info);position:relative;padding:1em;box-sizing:border-box;text-align:center;}\n"
        "\t\tdiv.box.error{border-color:var(--error);color:var(--error);}\n"
        "\t\tdiv.box.success{border-color:var(--success);color:var(--success);}\n"
        "\t\tdiv.arrow{position:absolute;height:20px;width:30px;z-index:10;background-repeat:no-repeat;background-size:contain;}\n"
        "\t\tdiv.arrow.response{left:-17.5px;bottom:calc(33.3333%% - 10px);}\n"
        "\t\tdiv.arrow.request{right:-17.5px;top:calc(33.3333%% - 10px);}\n"
        "\t\tdiv.border{flex:1px 0 0;background-color:var(--info);}\n"
        "\t\tdiv.border.error{background-color:var(--error);}\n"
        "\t\tdiv.border.success{background-color:var(--success);}\n"
        "\t\tdiv.content>span{display:block;color:var(--soft);font-size:0.75em;}\n"
        "\t\tdiv.content>img{height:3.75rem;margin:0.75rem auto;display:block;}\n"
        "\t\th3{font-size:2.25em;margin:0.75rem 0 0 0;color:unset;height:2.5rem;}\n"
        "\t\th4{font-size:1em;margin:0 0 0.75rem 0;color:unset;height:1.25rem;}\n"
        "\n"
        "\t\tdiv.arrow.request.success{background-image:url('data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMzAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHBhdGggZD0iTTEsMSBMMjUsMSBMMjksMTAgTDI1LDE5IEwxLDE5IiBmaWxsPSIjRkZG"
        "RkZGIiBzdHJva2U9IiMwMDgwMDAiIHN0cm9rZS13aWR0aD0iMiIvPjwvc3ZnPgo=');}\n"
        "\t\tdiv.arrow.request.error{background-image:url('data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMzAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHBhdGggZD0iTTEsMSBMMjUsMSBMMjksMTAgTDI1LDE5IEwxLDE5IiBmaWxsPSIjRkZG"
        "RkZGIiBzdHJva2U9IiNDMDAwMDAiIHN0cm9rZS13aWR0aD0iMiIvPjwvc3ZnPgo=');}\n"
        "\t\tdiv.arrow.response.success{background-image:url('data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMzAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHBhdGggZD0iTTI5LDE5IEw1LDE5IEwxLDEwIEw1LDEgTDI5LDEiIGZpbGw9IiNGRkZG"
        "RkYiIHN0cm9rZT0iIzAwODAwMCIgc3Ryb2tlLXdpZHRoPSIyIi8+PC9zdmc+Cg==');}\n"
        "\t\tdiv.arrow.response.error{background-image:url('data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMzAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHBhdGggZD0iTTI5LDE5IEw1LDE5IEwxLDEwIEw1LDEgTDI5LDEiIGZpbGw9IiNGRkZG"
        "RkYiIHN0cm9rZT0iI0MwMDAwMCIgc3Ryb2tlLXdpZHRoPSIyIi8+PC9zdmc+Cg==');}\n"
        "\n"
        "\t\t@media(prefers-color-scheme:dark){\n"
        "\t\t\thtml{color:#FFFFFF;--soft:#404040;}\n"
        "\t\t\tbody{background-color:#101010;}\n"
        "\t\t\tsection{background-color:#181818;}\n"
        "\n"
        "\t\t\tdiv.arrow.request.success{background-image:url('data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMzAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHBhdGggZD0iTTEsMSBMMjUsMSBMMjksMTAgTDI1LDE5IEwxLDE5IiBmaWxsPSIjMTgx"
        "ODE4IiBzdHJva2U9IiMwMDgwMDAiIHN0cm9rZS13aWR0aD0iMiIvPjwvc3ZnPgo=');}\n"
        "\t\t\tdiv.arrow.request.error{background-image:url('data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMzAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHBhdGggZD0iTTEsMSBMMjUsMSBMMjksMTAgTDI1LDE5IEwxLDE5IiBmaWxsPSIjMTgx"
        "ODE4IiBzdHJva2U9IiNDMDAwMDAiIHN0cm9rZS13aWR0aD0iMiIvPjwvc3ZnPgo=');}\n"
        "\t\t\tdiv.arrow.response.success{background-image:url('data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMzAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHBhdGggZD0iTTI5LDE5IEw1LDE5IEwxLDEwIEw1LDEgTDI5LDEiIGZpbGw9IiMxODE4"
        "MTgiIHN0cm9rZT0iIzAwODAwMCIgc3Ryb2tlLXdpZHRoPSIyIi8+PC9zdmc+Cg==');}\n"
        "\t\t\tdiv.arrow.response.error{background-image:url('data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMzAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHBhdGggZD0iTTI5LDE5IEw1LDE5IEwxLDEwIEw1LDEgTDI5LDEiIGZpbGw9IiMxODE4"
        "MTgiIHN0cm9rZT0iI0MwMDAwMCIgc3Ryb2tlLXdpZHRoPSIyIi8+PC9zdmc+Cg==');}\n"
        "\t\t}\n"
        "\t\t@media(min-width:650px){\n"
        "\t\t\tdiv.box:first-child{border-top-left-radius:4px;border-bottom-left-radius:4px;border-right:none;}\n"
        "\t\t\tdiv.box:last-child{border-top-right-radius:4px;border-bottom-right-radius:4px;border-left:none;}\n"
        "\t\t\tdiv.box:not(:last-child):not(:first-child){border-left:none;border-right:none;}\n"
        "\t\t}\n"
        "\t\t@media(max-width:650px){\n"
        "\t\t\tsection.error-ctx{flex-direction:column;height:unset;}\n"
        "\t\t\tdiv.box:first-child{border-top-left-radius:4px;border-top-right-radius:4px;border-bottom:none;padding-top:1em;}\n"
        "\t\t\tdiv.box:last-child{border-bottom-right-radius:4px;border-bottom-left-radius:4px;border-top:none;padding-bottom:1em;}\n"
        "\t\t\tdiv.box:not(:last-child):not(:first-child){border-top:none;border-bottom:none;}\n"
        "\t\t\tdiv.arrow.response{transform:rotate(90deg);top:-10px;left:calc(33.3333%% - 22.5px);right:unset;}\n"
        "\t\t\tdiv.arrow.request{transform:rotate(90deg);bottom:-10px;right:calc(33.3333%% - 22.5px);top:unset;}\n"
        "\t\t}\n"
        "\t</style>\n"
        "</head>\n"
        "<body>\n"
        "\t<main>\n"
        "\t\t<section>\n"
        "%3$s"
        "%9$s"
        "\t\t\t<div class=\"footer\"><a href=\"https://%7$s/\">%7$s</a> - " SERVER_STR_HTML "</div>\n"
        "\t\t</section>\n"
        "%8$s"
        "\t</main>\n"
        "</body>\n"
        "</html>\n";

const char http_rev_proxy_document[] =
        "\t\t<section class=\"error-ctx\">\n"
        "\t\t\t<div class=\"box%1$s\">\n"
        "\t\t\t\t<div class=\"content\">\n"
        "\t\t\t\t\t<span>Client</span>\n"
        "\t\t\t\t\t<img src=\"data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iNjQiIGhlaWdodD0iNjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHBhdGggZD0iTTIsMzIgYTMwLDMwLDAsMSwwLDYwLDAgYTMwLDMwLDAsMSwwLC02MCww"
        "IEw2MiwzMiBNNiwxNiBMNTgsMTYgTTYsNDggTDU4LDQ4IE0zMiwyIEwzMiw2MiBhMTUsMzAsMCwx"
        "LDAsMCwtNjAgYTE1LDMwLDAsMSwwLDAsNjAgWiIgc3Ryb2tlPSIjMDA4MDAwIiBzdHJva2Utd2lk"
        "dGg9IjIiIGZpbGw9IiMwMDAwMDAwMCIvPjwvc3ZnPgo=\"/>\n"
        "\t\t\t\t\t<span>Your Browser</span>\n"
        "\t\t\t\t</div>\n"
        "\t\t\t\t<div class=\"arrow request%2$s\"></div>\n"
        "\t\t\t</div>\n"
        "\t\t\t<div class=\"border%8$s\"></div>\n"
        "\t\t\t<div class=\"box%3$s\">\n"
        "\t\t\t\t<div class=\"content\">\n"
        "\t\t\t\t\t<span>Reverse Proxy</span>\n"
        "\t\t\t\t\t<h3>%10$03i</h3>\n"
        "\t\t\t\t\t<h4>%11$s</h4>\n"
        "\t\t\t\t\t<span>" SERVER_NAME "</span>\n"
        "\t\t\t\t</div>\n"
        "\t\t\t\t<div class=\"arrow request%4$s\"></div>\n"
        "\t\t\t\t<div class=\"arrow response%5$s\"></div>\n"
        "\t\t\t</div>\n"
        "\t\t\t<div class=\"border%9$s\"></div>\n"
        "\t\t\t<div class=\"box%6$s\">\n"
        "\t\t\t\t<div class=\"content\">\n"
        "\t\t\t\t\t<span>Server</span>\n"
        "\t\t\t\t\t<h3>%12$s</h3>\n"
        "\t\t\t\t\t<h4>%13$s</h4>\n"
        "\t\t\t\t\t<span>%14$s</span>\n"
        "\t\t\t\t</div>\n"
        "\t\t\t\t<div class=\"arrow response%7$s\"></div>\n"
        "\t\t\t</div>\n"
        "\t\t</section>\n";

const char http_error_document[] =
        "\t\t\t<h1>%1$i</h1>\n"
        "\t\t\t<h2>%2$s :&#xFEFF;(</h2>\n"
        "\t\t\t<p>%3$s</p>\n"
        "\t\t\t<p>%4$s</p>\n";

const char http_error_icon[] =
        "\t<link rel=\"alternate icon\" type=\"image/svg+xml\" sizes=\"any\" href=\"data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHRleHQgeD0iNCIgeT0iMTIiIGZpbGw9IiNDMDAwMDAiIHN0eWxlPSJmb250LWZhbWls"
        "eTonQXJpYWwnLHNhbnMtc2VyaWYiPjooPC90ZXh0Pjwvc3ZnPgo=\"/>\n";


const char http_warning_document[] =
        "\t\t\t<h1>%1$i</h1>\n"
        "\t\t\t<h2>%2$s :&#xFEFF;)</h2>\n"
        "\t\t\t<p>%3$s</p>\n"
        "\t\t\t<p>%4$s</p>\n";

const char http_warning_icon[] =
        "\t<link rel=\"alternate icon\" type=\"image/svg+xml\" sizes=\"any\" href=\"data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHRleHQgeD0iNCIgeT0iMTIiIGZpbGw9IiNFMEMwMDAiIHN0eWxlPSJmb250LWZhbWls"
        "eTonQXJpYWwnLHNhbnMtc2VyaWYiPjopPC90ZXh0Pjwvc3ZnPgo=\"/>\n";


const char http_success_document[] =
        "\t\t\t<h1>%1$i</h1>\n"
        "\t\t\t<h2>%2$s :&#xFEFF;)</h2>\n"
        "\t\t\t<p>%3$s</p>\n"
        "\t\t\t<p>%4$s</p>\n";

const char http_success_icon[] =
        "\t<link rel=\"alternate icon\" type=\"image/svg+xml\" sizes=\"any\" href=\"data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHRleHQgeD0iNCIgeT0iMTIiIGZpbGw9IiMwMDgwMDAiIHN0eWxlPSJmb250LWZhbWls"
        "eTonQXJpYWwnLHNhbnMtc2VyaWYiPjopPC90ZXh0Pjwvc3ZnPgo=\"/>\n";


const char http_info_document[] =
        "\t\t\t<h1>%1$i</h1>\n"
        "\t\t\t<h2>%2$s :&#xFEFF;)</h2>\n"
        "\t\t\t<p>%3$s</p>\n"
        "\t\t\t<p>%4$s</p>\n";

const char http_info_icon[] =
        "\t<link rel=\"alternate icon\" type=\"image/svg+xml\" sizes=\"any\" href=\"data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHRleHQgeD0iNCIgeT0iMTIiIGZpbGw9IiM2MDYwNjAiIHN0eWxlPSJmb250LWZhbWls"
        "eTonQXJpYWwnLHNhbnMtc2VyaWYiPjopPC90ZXh0Pjwvc3ZnPgo=\"/>\n";

const int http_statuses_size = sizeof(http_statuses);
const int http_status_messages_size = sizeof(http_status_messages);
