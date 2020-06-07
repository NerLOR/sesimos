

#ifndef NECRONDA_HTTP_RESPONSE
#define NECRONDA_HTTP_RESPONSE


#include <string>
#include "HttpHeader.h"
#include "HttpStatusCode.h"
#include "../Socket.h"

class HttpResponse {
private:
	HttpHeader header;
	HttpStatusCode statuscode;
	string version;

public:
	HttpResponse();

	explicit HttpResponse(Socket *socket);

	explicit HttpResponse(int statuscode, string version = "1.1");

	explicit HttpResponse(HttpStatusCode statuscode, string version = "1.1");

	void parseHeader(Socket *socket);

	void sendHeader(Socket *socket);

	string getField(string index);

	void setField(string index, string data);

	bool isExistingField(string index);

	HttpStatusCode getStatusCode();

	string getVersion();

	void setStatusCode(HttpStatusCode statuscode);

	void setStatusCode(int statuscode);

	void setVersion(string version);

	void removeField(string index);
};

#endif
