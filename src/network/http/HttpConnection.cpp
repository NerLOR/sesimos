

#include <zlib.h>
#include <cassert>
#include <iostream>
#include <utility>
#include "HttpConnection.h"
#include "../Socket.h"
#include "HttpStatusCode.h"
#include "Http.h"


HttpConnection::HttpConnection() = default;

HttpConnection::HttpConnection(Socket *socket) {
    this->socket = socket;
    this->request = new HttpRequest(socket);
    this->response = new HttpResponse();
    microsStart = getMicros();
    response->setVersion("1.1");
    response->setField("Server", "Necronda/3.0");
}

void HttpConnection::respond(int statuscode) {
    if (statuscode >= 400 && statuscode < 600) {
        respond(statuscode,
                "<!DOCTYPE html><html><head><title>" + to_string(statuscode) + " " +
                ::getStatusCode(statuscode).message +
                "</title></head><body><center><h1>" + to_string(statuscode) + " " +
                ::getStatusCode(statuscode).message +
                "</h1>" +
                ((request->isExistingField("Host")) ?
                 (request->isExistingField("Referer") &&
                  request->getField("Referer").find(request->getField("Host")) != string::npos) ?
                 "<p>Go back to the last page you visited: <a href=\"" + request->getField("Referer") + "\">" +
                 request->getField("Referer") + "</a></p>" :
                 "<p>Go back to the home page of <a href=\"//" +
                 request->getField("Host") + "/\">" +
                 request->getField("Host") +
                 "</a></p>" : "") + "</center></body></html>\r\n"
        );
    } else {
        respond(statuscode, "");
    }
}

void HttpConnection::respond(int statuscode, string payload) {
    response->setStatusCode(statuscode);
    response->setField("Date", getHttpDate());
    response->setField("Content-Length", to_string(payload.length()));
    response->sendHeader(socket);
    socket->send(std::move(payload));
}

void HttpConnection::respond(int statuscode, FILE *file, bool compress, long start, long end) {
    response->setStatusCode(statuscode);
    response->setField("Transfer-Encoding", "chunked");
    response->setField("Date", getHttpDate());

    long shouldTransfer;
    long transfered = 0;

    fseek(file, 0, SEEK_END);
    long len = ftell(file);

    if (start != -1 && end != -1) {
        fseek(file, start, SEEK_SET);
        response->setField("Content-Length", to_string(end - start + 1));
        shouldTransfer = end - start + 1;
        compress = false;
    } else {
        fseek(file, 0, SEEK_SET);
        shouldTransfer = len;
        if (len >= 0 && !compress) {
            response->setField("Content-Length", to_string(len));
        }
    }

    if (compress) {
        response->setField("Content-Encoding", "deflate");
    }

    response->sendHeader(socket);

    if (compress) {
        int level = 1;
        int ret, flush;
        unsigned have;
        z_stream strm;
        unsigned char in[CPPNET_CHUNK];
        unsigned char out[CPPNET_CHUNK];

        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        ret = deflateInit(&strm, level);
        if (ret != Z_OK) {
            throw (char *) "Unable to open file";
        }

        do {
            strm.avail_in = (uInt) fread(in, 1, CPPNET_CHUNK, file);

            if (ferror(file)) {
                (void) deflateEnd(&strm);
                throw (char *) strerror(errno);
            }
            flush = feof(file) ? Z_FINISH : Z_NO_FLUSH;
            strm.next_in = in;
            do {
                strm.avail_out = CPPNET_CHUNK;
                strm.next_out = out;
                ret = deflate(&strm, flush);
                assert(ret != Z_STREAM_ERROR);
                have = CPPNET_CHUNK - strm.avail_out;

                if (have != 0) {
                    char buffer[64];
                    sprintf(buffer, "%X\r\n", have);
                    socket->send(buffer);
                    socket->send((const char *) out, have);
                    socket->send("\r\n");
                }
            } while (strm.avail_out == 0);
            assert(strm.avail_in == 0);
        } while (flush != Z_FINISH);
        assert(ret == Z_STREAM_END);
        socket->send("0\r\n\r\n");
        deflateEnd(&strm);
    } else {
        char buffer[CPPNET_CHUNK];
        char buff[64];
        while (true) {
            unsigned long size = fread(buffer, 1, (size_t) ((CPPNET_CHUNK > (shouldTransfer - transfered) && shouldTransfer > 0) ? (shouldTransfer - transfered) : CPPNET_CHUNK), file);
            transfered += size;
            sprintf(buff, "%lX\r\n", size);
            socket->send(buff);
            socket->send((const char *) buffer, size);
            socket->send("\r\n");
            if (size == 0) {
                break;
            }
        }
    }
}

string HttpConnection::getField(string index) {
    return request->getField(std::move(index));
}

string HttpConnection::getPath() {
    return request->getPath();
}

void HttpConnection::setField(string index, string data) {
    response->setField(std::move(index), std::move(data));
}

bool HttpConnection::isExistingField(string index) {
    return request->isExistingField(std::move(index));
}

string HttpConnection::getMethod() {
    return request->getMethod();
}

long HttpConnection::getDuration() {
    return getMicros() - microsStart;
}

HttpStatusCode HttpConnection::getStatusCode() {
    return response->getStatusCode();
}

void HttpConnection::redirect(int statuscode, string location) {
    setField("Location", std::move(location));
    respond(statuscode, "");
}

string HttpConnection::getResponseField(string index) {
    return response->getField(std::move(index));
}

bool HttpConnection::isExistingResponseField(string index) {
    return response->isExistingField(std::move(index));
}

string HttpConnection::cgiExport() {
    return request->cgiExport();
}

void HttpConnection::removeField(string index) {
    response->removeField(std::move(index));
}
