/**
 * sesimos - secure, simple, modern web server
 * @brief HTTP static implementation
 * @file src/lib/http_static.c
 * @author Lorenz Stechauner
 * @date 2021-05-03
 * @details https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
 */

#include "http.h"

const http_status http_statuses[] = {
        {100, HTTP_TYPE_INFORMATIONAL, "Continue"},
        {101, HTTP_TYPE_INFORMATIONAL, "Switching Protocols"},
        {102, HTTP_TYPE_INFORMATIONAL, "Processing"},
        {103, HTTP_TYPE_INFORMATIONAL, "Early Hints"},

        {200, HTTP_TYPE_SUCCESS,       "OK"},
        {201, HTTP_TYPE_SUCCESS,       "Created"},
        {202, HTTP_TYPE_SUCCESS,       "Accepted"},
        {203, HTTP_TYPE_SUCCESS,       "Non-Authoritative Information"},
        {204, HTTP_TYPE_SUCCESS,       "No Content"},
        {205, HTTP_TYPE_SUCCESS,       "Reset Content"},
        {206, HTTP_TYPE_SUCCESS,       "Partial Content"},
        {207, HTTP_TYPE_SUCCESS,       "Multi-Status"},
        {208, HTTP_TYPE_SUCCESS,       "Already Reported"},
        {226, HTTP_TYPE_SUCCESS,       "Instance Manipulation Used"},

        {300, HTTP_TYPE_REDIRECTION,   "Multiple Choices"},
        {301, HTTP_TYPE_REDIRECTION,   "Moved Permanently"},
        {302, HTTP_TYPE_REDIRECTION,   "Found"},
        {303, HTTP_TYPE_REDIRECTION,   "See Other"},
        {304, HTTP_TYPE_SUCCESS,       "Not Modified"},
        {305, HTTP_TYPE_REDIRECTION,   "Use Proxy"},
        {307, HTTP_TYPE_REDIRECTION,   "Temporary Redirect"},
        {308, HTTP_TYPE_REDIRECTION,   "Permanent Redirect"},

        {400, HTTP_TYPE_CLIENT_ERROR,  "Bad Request"},
        {401, HTTP_TYPE_CLIENT_ERROR,  "Unauthorized"},
        {402, HTTP_TYPE_CLIENT_ERROR,  "Payment Required"},
        {403, HTTP_TYPE_CLIENT_ERROR,  "Forbidden"},
        {404, HTTP_TYPE_CLIENT_ERROR,  "Not Found"},
        {405, HTTP_TYPE_CLIENT_ERROR,  "Method Not Allowed"},
        {406, HTTP_TYPE_CLIENT_ERROR,  "Not Acceptable"},
        {407, HTTP_TYPE_CLIENT_ERROR,  "Proxy Authentication Required"},
        {408, HTTP_TYPE_CLIENT_ERROR,  "Request Timeout"},
        {409, HTTP_TYPE_CLIENT_ERROR,  "Conflict"},
        {410, HTTP_TYPE_CLIENT_ERROR,  "Gone"},
        {411, HTTP_TYPE_CLIENT_ERROR,  "Length Required"},
        {412, HTTP_TYPE_CLIENT_ERROR,  "Precondition Failed"},
        {413, HTTP_TYPE_CLIENT_ERROR,  "Request Entity Too Large"},
        {414, HTTP_TYPE_CLIENT_ERROR,  "Request-URI Too Long"},
        {415, HTTP_TYPE_CLIENT_ERROR,  "Unsupported Media Type"},
        {416, HTTP_TYPE_CLIENT_ERROR,  "Range Not Satisfiable"},
        {417, HTTP_TYPE_CLIENT_ERROR,  "Expectation Failed"},
        {421, HTTP_TYPE_CLIENT_ERROR,  "Misdirected Request"},
        {422, HTTP_TYPE_CLIENT_ERROR,  "Unprocessable Content"},
        {423, HTTP_TYPE_CLIENT_ERROR,  "Locked"},
        {424, HTTP_TYPE_CLIENT_ERROR,  "Failed Dependency"},
        {425, HTTP_TYPE_CLIENT_ERROR,  "Too Early"},
        {426, HTTP_TYPE_CLIENT_ERROR,  "Upgrade Required"},
        {428, HTTP_TYPE_CLIENT_ERROR,  "Precondition Required"},
        {429, HTTP_TYPE_CLIENT_ERROR,  "Too Many Requests"},
        {431, HTTP_TYPE_CLIENT_ERROR,  "Request Header Fields Too Large"},
        {451, HTTP_TYPE_CLIENT_ERROR,  "Unavailable For Legal Reasons"},

        {500, HTTP_TYPE_SERVER_ERROR,  "Internal Server Error"},
        {501, HTTP_TYPE_SERVER_ERROR,  "Not Implemented"},
        {502, HTTP_TYPE_SERVER_ERROR,  "Bad Gateway"},
        {503, HTTP_TYPE_SERVER_ERROR,  "Service Unavailable"},
        {504, HTTP_TYPE_SERVER_ERROR,  "Gateway Timeout"},
        {505, HTTP_TYPE_SERVER_ERROR,  "HTTP Version Not Supported"},
        {506, HTTP_TYPE_SERVER_ERROR,  "Variant Also Negotiates"},
        {507, HTTP_TYPE_SERVER_ERROR,  "Insufficient Storage"},
        {508, HTTP_TYPE_SERVER_ERROR,  "Loop Detected"},
        {511, HTTP_TYPE_SERVER_ERROR,  "Network Authentication Required"},
};

// TODO add remaining descriptions
const http_status_msg http_status_messages[] = {
        {100, "The client SHOULD continue with its request. The server MUST send a final response after the request "
              "has been completed."},
        {101, "The server understands and is willing to comply with the clients request, via the Upgrade message "
              "header field, for a change in the application protocol being used on this connection."},
        {102, "The server has a reasonable expectation that the request will take significant time to complete. The "
              "server MUST send a final response after the request has been completed."},
        {103, "The client can speculatively evaluate the header fields included in the response while waiting for the "
              "final response. The server MUST send a final response after the request has been completed."},

        {200, "The request has succeeded."},
        {201, "The request has been fulfilled and resulted in a new resource being created."},
        {202, "The request has been accepted for processing, but the processing has not been completed."},
        {203, "The returned meta information in the entity-header is not the definitive set as available from the "
              "origin server, but is gathered from a local or a third-party copy."},
        {204, "The server has fulfilled the request but does not need to return an entity-body, and might want to "
              "return updated meta information."},
        {205, "The server has fulfilled the request and the user agent SHOULD reset the document view which caused the "
              "request to be sent."},
        {206, "The server has fulfilled the partial GET request for the resource."},
        {207, "The response provides status for multiple independent operations."},
        {208, "The response is used to avoid enumerating the internal members of multiple bindings to the same "
              "collection repeatedly."},
        {226, "The server has fulfilled a GET request for the resource, and the response is a representation of the "
              "result of one or more instance-manipulations applied to the current instance."},

        {300, "The requested resource corresponds to any one of a set of representations, each with its own specific "
              "location, and agent-driven negotiation information is being provided so that the user (or user agent) "
              "can select a preferred representation and redirect its request to that location."},
        {301, "The requested resource has been assigned a new permanent URI and any future references to this resource "
              "SHOULD use one of the returned URIs."},
        {302, "The requested resource resides temporarily under a different URI."},
        {303, "The response to the request can be found under a different URI and SHOULD be retrieved using a GET "
              "method on that resource."},
        {304, "The request has been fulfilled and the requested resource has not been modified."},
        {305, "The requested resource MUST be accessed through the proxy given by the Location field."},
        {307, "The requested resource resides temporarily under a different URI."},
        {308, "The requested resource has been assigned a new permanent URI and any future references to this resource "
              "ought to use one of the enclosed URIs."},

        {400, "The request could not be understood by the server due to malformed syntax."},
        {401, "The request requires user authentication."},
        {403, "The server understood the request, but is refusing to fulfill it."},
        {404, "The server has not found anything matching the Request-URI."},
        {405, "The method specified in the Request-Line is not allowed for the resource identified by the "
              "Request-URI."},
        {406, "The resource identified by the request is only capable of generating response entities which have "
              "content characteristics not acceptable according to the accept headers sent in the request."},
        {407, "The request requires user authentication on the proxy."},
        {408, "The client did not produce a request within the time that the server was prepared to wait."},
        {409, "The request could not be completed due to a conflict with the current state of the resource."},
        {410, "The requested resource is no longer available at the server and no forwarding address is known."},
        {411, "The server refuses to accept the request without a defined Content-Length."},
        {412, "The precondition given in one or more of the request-header fields evaluated to false when it was "
              "tested on the server."},
        {413, "The server is refusing to process a request because the request entity is larger than the server is "
              "willing or able to process."},
        {414, "The server is refusing to service the request because the Request-URI is longer than the server is "
              "willing to interpret."},
        {415, "The server is refusing to service the request because the entity of the request is in a format not "
              "supported by the requested resource for the requested method."},
        {416, "None of the ranges in the requests Range header field overlap the current extent of the selected "
              "resource or that the set of ranges requested has been rejected due to invalid ranges or an excessive "
              "request of small or overlapping ranges."},
        {417, "The expectation given in an Expect request-header field could not be met by this server, or, if the "
              "server is a proxy, the server has unambiguous evidence that the request could not be met by the "
              "next-hop server."},
        {421, "The server is not able to produce a response. The client MAY retry the request over a different "
              "connection."},
        {422, ""},
        {423, ""},
        {424, ""},
        {425, ""},
        {426, ""},
        {428, ""},
        {429, ""},
        {431, ""},
        {451, ""},

        {500, "The server encountered an unexpected condition which prevented it from fulfilling the request."},
        {501, "The server does not support the functionality required to fulfill the request."},
        {502, "The server, while acting as a gateway or proxy, received an invalid response from the upstream server "
              "it accessed in attempting to fulfill the request."},
        {503, "The server is currently unable to handle the request due to a temporary overloading or maintenance of "
              "the server."},
        {504, "The server, while acting as a gateway or proxy, did not receive a timely response from the upstream "
              "server specified by the URI or some other auxiliary server it needed to access in attempting to "
              "complete the request."},
        {505, "The server does not support, or refuses to support, the HTTP protocol version that was used in the "
              "request message."},
        {506, ""},
        {507, ""},
        {508, ""},
        {511, ""},
};

const int http_statuses_size = sizeof(http_statuses) / sizeof(http_status);
const int http_status_messages_size = sizeof(http_status_messages) / sizeof(http_status_msg);

const char http_error_doc[] =
        "      <h1>%1$i</h1>\n"
        "      <h2>%2$s :&#xFEFF;(</h2>\n"
        "      <p>%3$s</p>\n"
        "      <p>%4$s</p>\n";

const char http_warning_doc[] =
        "      <h1>%1$i</h1>\n"
        "      <h2>%2$s :&#xFEFF;)</h2>\n"
        "      <p>%3$s</p>\n"
        "      <p>%4$s</p>\n";

const char http_success_doc[] =
        "      <h1>%1$i</h1>\n"
        "      <h2>%2$s :&#xFEFF;)</h2>\n"
        "      <p>%3$s</p>\n"
        "      <p>%4$s</p>\n";

const char http_info_doc[] =
        "      <h1>%1$i</h1>\n"
        "      <h2>%2$s :&#xFEFF;)</h2>\n"
        "      <p>%3$s</p>\n"
        "      <p>%4$s</p>\n";
