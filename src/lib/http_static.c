/**
 * sesimos - secure, simple, modern web server
 * @brief HTTP static implementation
 * @file src/lib/http_static.c
 * @author Lorenz Stechauner
 * @date 2021-05-03
 */

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

const int http_statuses_size = sizeof(http_statuses) / sizeof(http_status);
const int http_status_messages_size = sizeof(http_status_messages) / sizeof(http_status_msg);

const char http_error_doc[] =
        "      <h1>%1$i</h1>\n"
        "      <h2>%2$s :&#xFEFF;(</h2>\n"
        "      <p>%3$s</p>\n"
        "      <p>%4$s</p>\n";

const char http_error_icon[] =
        "  <link rel=\"alternate icon\" type=\"image/svg+xml\" sizes=\"any\" href=\"data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHRleHQgeD0iNCIgeT0iMTIiIGZpbGw9IiNDMDAwMDAiIHN0eWxlPSJmb250LWZhbWls"
        "eTonQXJpYWwnLHNhbnMtc2VyaWYiPjooPC90ZXh0Pjwvc3ZnPgo=\"/>\n";


const char http_warning_doc[] =
        "      <h1>%1$i</h1>\n"
        "      <h2>%2$s :&#xFEFF;)</h2>\n"
        "      <p>%3$s</p>\n"
        "      <p>%4$s</p>\n";

const char http_warning_icon[] =
        "  <link rel=\"alternate icon\" type=\"image/svg+xml\" sizes=\"any\" href=\"data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHRleHQgeD0iNCIgeT0iMTIiIGZpbGw9IiNFMEMwMDAiIHN0eWxlPSJmb250LWZhbWls"
        "eTonQXJpYWwnLHNhbnMtc2VyaWYiPjopPC90ZXh0Pjwvc3ZnPgo=\"/>\n";


const char http_success_doc[] =
        "      <h1>%1$i</h1>\n"
        "      <h2>%2$s :&#xFEFF;)</h2>\n"
        "      <p>%3$s</p>\n"
        "      <p>%4$s</p>\n";

const char http_success_icon[] =
        "  <link rel=\"alternate icon\" type=\"image/svg+xml\" sizes=\"any\" href=\"data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHRleHQgeD0iNCIgeT0iMTIiIGZpbGw9IiMwMDgwMDAiIHN0eWxlPSJmb250LWZhbWls"
        "eTonQXJpYWwnLHNhbnMtc2VyaWYiPjopPC90ZXh0Pjwvc3ZnPgo=\"/>\n";


const char http_info_doc[] =
        "      <h1>%1$i</h1>\n"
        "      <h2>%2$s :&#xFEFF;)</h2>\n"
        "      <p>%3$s</p>\n"
        "      <p>%4$s</p>\n";

const char http_info_icon[] =
        "  <link rel=\"alternate icon\" type=\"image/svg+xml\" sizes=\"any\" href=\"data:image/svg+xml;base64,"
        "PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAw"
        "L3N2ZyI+PHRleHQgeD0iNCIgeT0iMTIiIGZpbGw9IiM2MDYwNjAiIHN0eWxlPSJmb250LWZhbWls"
        "eTonQXJpYWwnLHNhbnMtc2VyaWYiPjopPC90ZXh0Pjwvc3ZnPgo=\"/>\n";
