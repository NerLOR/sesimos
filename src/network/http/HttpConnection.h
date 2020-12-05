

#ifndef NECRONDA_HTTP_CONNECTION
#define NECRONDA_HTTP_CONNECTION


#include "../Socket.h"
#include "HttpResponse.h"
#include "HttpRequest.h"


class HttpConnection {
private:
    Socket *socket{};
    HttpRequest *request{};
    HttpResponse *response{};
    unsigned long microsStart{};

public:
    explicit HttpConnection();

    explicit HttpConnection(Socket *socket);

    void respond(int statuscode);

    void respond(int statuscode, string payload);

    void respond(int statuscode, FILE *file, bool compress = false, long start = -1, long end = -1);

    void redirect(int statuscode, string location);

    bool isExistingField(string index);

    bool isExistingResponseField(string index);

    string getField(string index);

    string getResponseField(string index);

    string getPath();

    string getMethod();

    void setField(string index, string data);

    unsigned long getDuration();

    unsigned long getMicrosStart();

    HttpStatusCode getStatusCode();

    string cgiExport();

    void removeField(string index);
};

#endif
