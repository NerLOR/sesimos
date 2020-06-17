/**
 * Necronda Web Server 3.0
 * HttpHeader.h - HttpHeader Class definition
 * Lorenz Stechauner, 2018-05-09
 */

#ifndef NECRONDA_HTTP_REQUEST
#define NECRONDA_HTTP_REQUEST

using namespace std;

class HttpRequest {
private:
    HttpHeader header;
    string method;
    string path;
    string version;

public:
    HttpRequest();

    explicit HttpRequest(Socket *socket);

    HttpRequest(string method, string path, string version = "1.1");

    void parseHeader(Socket *socket);

    void sendHeader(Socket *socket);

    string getField(string index);

    void setField(string index, string data);

    bool isExistingField(string index);

    string getMethod();

    string getPath();

    string getVersion();

    void setMethod(string method);

    void setPath(string path);

    void setVersion(string version);

    string cgiExport();

};

#endif
