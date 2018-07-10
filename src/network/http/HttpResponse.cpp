//
// Created by lorenz on 5/17/18.
//

#include "HttpResponse.h"
#include <utility>
#include <iostream>
#include "HttpStatusCode.h"


HttpResponse::HttpResponse() {
	this->header = HttpHeader();
}

HttpResponse::HttpResponse(Socket *socket) : HttpResponse::HttpResponse() {
	this->parseHeader(socket);
}

HttpResponse::HttpResponse(int statuscode, string version) : HttpResponse::HttpResponse(::getStatusCode(statuscode), std::move(version)) {
}

HttpResponse::HttpResponse(HttpStatusCode statuscode, string version) : HttpResponse::HttpResponse() {
	this->statuscode = statuscode;
	this->version = std::move(version);
}

void HttpResponse::sendHeader(Socket *socket) {
	socket->send("HTTP/" + version + " " + to_string(statuscode.code) + " " + statuscode.message + "\r\n" +
			header.toString() + "\r\n");
}

string HttpResponse::getField(string index) {
	return header.getField(std::move(index));
}

void HttpResponse::setField(string index, string data) {
	header.setField(std::move(index), std::move(data));
}

bool HttpResponse::isExistingField(string index) {
	return header.isExistingField(std::move(index));
}

HttpStatusCode HttpResponse::getStatusCode() {
	return statuscode;
}

string HttpResponse::getVersion() {
	return version;
}

void HttpResponse::setStatusCode(HttpStatusCode statuscode) {
	this->statuscode = statuscode;
}

void HttpResponse::setStatusCode(int statuscode) {
	this->statuscode = ::getStatusCode(statuscode);
}

void HttpResponse::setVersion(string version) {
	this->version = std::move(version);
}

void HttpResponse::parseHeader(Socket *socket) {

}

void HttpResponse::removeField(string index) {
	header.removeField(std::move(index));
}
