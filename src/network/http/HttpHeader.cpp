/**
 * Necronda Web Server 3.0
 * HttpHeader.cpp - HttpHeader Class methods
 * Lorenz Stechauner, 2018-05-09
 */


#include <map>
#include <iostream>
#include "../Socket.h"

#include "HttpHeader.h"


using namespace std;

string to_cgi(string text) {
    for (auto & c: text) c = (char) toupper(c);
    long pos = 0;
    while ((pos = text.find('-', pos + 1)) != string::npos) {
        text.replace(pos, 1, 1, '_');
    }
    return text;
}


/**
 * Default Constructor
 */
HttpHeader::HttpHeader() {
    fields = fields;
}

HttpHeader::HttpHeader(Socket *socket) : HttpHeader::HttpHeader() {
    parse(socket);
}


void HttpHeader::parse(Socket *socket) {
    while (true) {
        string line = socket->receiveLine();
        if (line.length() == 0) {
            break;
        } else {
            unsigned long pos = line.find(':');
            if (pos == string::npos) {
                throw (char *) "Malformed header";
            }
            string index = line.substr(0, pos);
            string data = line.substr(pos + 1, line.length() - pos);
            while (index[0] == ' ') index.erase(index.begin() + 0);
            while (index[index.length() - 1] == ' ') index.erase(index.end() - 1);
            while (data[0] == ' ') data.erase(data.begin() + 0);
            while (data[data.length() - 1] == ' ') data.erase(data.end() - 1);
            setField(index, data);
        }
    }
}


/**
 * Default Destructor
 */
HttpHeader::~HttpHeader() {
    fields.clear();
}


/**
 * Sets a field in the HTTP header
 * e.g. Content-Length: 42
 * @param index The field index
 * @param data The field data
 */
void HttpHeader::setField(string index, string data) {
    removeField(index);
    fields.insert(make_pair(index, data));
}

void HttpHeader::removeField(string index) {
    fields.erase(index);
}

/**
 * Gets a field from the HTTP header
 * e.g. Content-Length: 42
 * @param index The field index
 * @return The field data
 */
string HttpHeader::getField(string index) {
    auto i = fields.find(index);
    if (i != fields.end()) {
        return fields.at(index);
    } else {
        return "";
    }
}


bool HttpHeader::isExistingField(string index) {
    auto i = fields.find(index);
    return i != fields.end();
}

string HttpHeader::toString() {
    string header = "";
    for (auto it = fields.begin(); it != fields.end(); it++ ) {
        header += it->first + ": " + it->second + "\r\n";
    }
    return header;
}

string HttpHeader::cgiExport() {
    string header = "";
    for (auto it = fields.begin(); it != fields.end(); it++ ) {
        header += "HTTP_" + to_cgi(it->first) + "=" + cli_encode(it->second) + " ";
    }
    return header;
}



