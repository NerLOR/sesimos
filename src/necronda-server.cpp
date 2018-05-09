/**
 * Necronda Web Server 3.0
 * necronda-server.cpp - Main Executable
 * Lorenz Stechauner, 2018-05-09
 */


#include <iostream>

#include "http/HttpHeader.cpp"


using namespace std;

int main() {
    cout << "Hello, World!1" << endl;
	HttpHeader *header = new HttpHeader();

	header->setField("Content-Length", "80");
	header->setField("Hermann", "500");

	cout << header->getField("Content-Length")  << " " << header->getField("Hermand") << endl;
    return 0;
}

