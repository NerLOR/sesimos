

#include <string>
#include <utility>
#include <iostream>
#include "../Socket.h"
#include "HttpHeader.h"
#include "HttpRequest.h"


HttpRequest::HttpRequest() {
    this->header = HttpHeader();
}

HttpRequest::HttpRequest(Socket *socket) : HttpRequest::HttpRequest() {
    parseHeader(socket);
}

HttpRequest::HttpRequest(string method, string path, string version) : HttpRequest::HttpRequest() {
    this->method = std::move(method);
    this->path = std::move(path);
    this->version = std::move(version);
}

void HttpRequest::parseHeader(Socket *socket) {
    string line = socket->receiveLine();

    unsigned long pos1 = line.find(' ');
    unsigned long pos2;

    bool invalid = false;

    if (pos1 != string::npos) {
        pos2 = line.find(' ', pos1 + 1);
        if (pos2 != string::npos) {
            method = line.substr(0, pos1);
            for (auto &c: method) c = (char) toupper(c);
            path = line.substr(pos1 + 1, pos2 - pos1 - 1);
            version = line.substr(pos2 + 6, 3);
        } else {
            invalid = true;
        }
    } else {
        pos2 = string::npos;
        invalid = true;
    }


    if (!invalid && (line.substr(pos2 + 1, 5) != "HTTP/" || version[1] != '.' || path[0] != '/' || !(version[0] >= '0' && version[0] <= '9') || !(version[2] >= '0' && version[2] <= '9'))) {
        invalid = true;
    }

    if (invalid) {
        method = "";
        path = "";
        version = "";
        throw (char *) "Malformed header";
    }

    header.parse(socket);
}

string HttpRequest::getMethod() {
    return method;
}

string HttpRequest::getPath() {
    return path;
}

string HttpRequest::getVersion() {
    return version;
}

void HttpRequest::setMethod(string method) {
    this->method = std::move(method);
}

void HttpRequest::setPath(string path) {
    this->path = std::move(path);
}

void HttpRequest::setVersion(string version) {
    this->version = std::move(version);
}

string HttpRequest::getField(string index) {
    return header.getField(std::move(index));
}

void HttpRequest::setField(string index, string data) {
    header.setField(std::move(index), std::move(data));
}

bool HttpRequest::isExistingField(string index) {
    return header.isExistingField(std::move(index));
}

string HttpRequest::cgiExport() {
    return header.cgiExport();
}






