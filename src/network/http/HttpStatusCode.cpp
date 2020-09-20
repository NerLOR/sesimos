#include "HttpStatusCode.h"

/**
 * Necronda Web Server 3.0
 * HttpStatusCode.cpp - HTTP Status Code definition
 * Lorenz Stechauner, 2018-05-16
 * Reference: https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
 */


HttpStatusCode httpStatusCodes[] = {
        HttpStatusCode{100, "Informational", "Continue", ""},
        HttpStatusCode{101, "Informational", "Switching Protocols", ""},

        HttpStatusCode{200, "Success",       "OK", ""},
        HttpStatusCode{201, "Success",       "Created", ""},
        HttpStatusCode{202, "Success",       "Accepted", ""},
        HttpStatusCode{203, "Success",       "Non-Authoritative Information", ""},
        HttpStatusCode{204, "Success",       "No Content", ""},
        HttpStatusCode{205, "Success",       "Reset Content", ""},
        HttpStatusCode{206, "Success",       "Partial Content", ""},

        HttpStatusCode{300, "Redirection",   "Multiple Choices", ""},
        HttpStatusCode{301, "Redirection",   "Moved Permanently", ""},
        HttpStatusCode{302, "Redirection",   "Found", ""},
        HttpStatusCode{303, "Redirection",   "See Other", ""},
        HttpStatusCode{304, "Redirection",   "Not Modified", ""},
        HttpStatusCode{305, "Redirection",   "Use Proxy", ""},
        HttpStatusCode{307, "Redirection",   "Temporary Redirect", ""},
        HttpStatusCode{308, "Redirection",   "Permanent Redirect", ""},

        HttpStatusCode{400, "Client Error",  "Bad Request", ""},
        HttpStatusCode{401, "Client Error",  "Unauthorized", ""},
        HttpStatusCode{402, "Client Error",  "Payment Required", ""},
        HttpStatusCode{403, "Client Error",  "Forbidden", ""},
        HttpStatusCode{404, "Client Error",  "Not Found", ""},
        HttpStatusCode{405, "Client Error",  "Method Not Allowed", ""},
        HttpStatusCode{406, "Client Error",  "Not Acceptable", ""},
        HttpStatusCode{407, "Client Error",  "Proxy Authentication Required", ""},
        HttpStatusCode{408, "Client Error",  "Request Timeout", ""},
        HttpStatusCode{409, "Client Error",  "Conflict", ""},
        HttpStatusCode{410, "Client Error",  "Gone", ""},
        HttpStatusCode{411, "Client Error",  "Length Required", ""},
        HttpStatusCode{412, "Client Error",  "Precondition Failed", ""},
        HttpStatusCode{413, "Client Error",  "Request Entity Too Large", ""},
        HttpStatusCode{414, "Client Error",  "Request-URI Too Long", ""},
        HttpStatusCode{415, "Client Error",  "Unsupported Media Type", ""},
        HttpStatusCode{416, "Client Error",  "Requested Range Not Satisfiable", ""},
        HttpStatusCode{417, "Client Error",  "Expectation Failed", ""},

        HttpStatusCode{500, "Server Error",  "Internal Server Error", ""},
        HttpStatusCode{501, "Server Error",  "Not Implemented", ""},
        HttpStatusCode{502, "Server Error",  "Bad Gateway", ""},
        HttpStatusCode{503, "Server Error",  "Service Unavailable", ""},
        HttpStatusCode{504, "Server Error",  "Gateway Timeout", ""},
        HttpStatusCode{505, "Server Error",  "HTTP Version Not Supported", ""},
};

HttpStatusCode getStatusCode(int statuscode) {
    for (HttpStatusCode sc : httpStatusCodes) {
        if (sc.code == statuscode) {
            return sc;
        }
    }
    throw (char *) "Invalid status code";
}
