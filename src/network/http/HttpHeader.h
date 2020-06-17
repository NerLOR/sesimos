/**
 * Necronda Web Server 3.0
 * HttpHeader.h - HttpHeader Class definition
 * Lorenz Stechauner, 2018-05-09
 */

#ifndef NECRONDA_HTTP_HEADER
#define NECRONDA_HTTP_HEADER

#include <cstring>

using namespace std;

struct comp {
    bool operator()(const std::string& lhs, const std::string& rhs) const {
        return strcasecmp(lhs.c_str(), rhs.c_str()) < 0;
    }
};

/**
 * Stores Key-Value Pairs for a HTTP header
 * e.g.
 * Content-Length: 64
 * Host: example.org
 */
class HttpHeader {
private:
    map<string, string, comp> fields;

public:
    HttpHeader();

    explicit HttpHeader(Socket *socket);

    ~HttpHeader();

    void setField(string index, string data);

    string getField(string index);

    void removeField(string index);

    bool isExistingField(string index);

    void parse(Socket *socket);

    string toString();

    string cgiExport();

};

#endif
