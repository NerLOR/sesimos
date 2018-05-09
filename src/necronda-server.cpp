/**
 * Necronda Web Server 3.0
 * necronda-server.cpp - Main Executable
 * Lorenz Stechauner, 2018-05-09
 */


#include <iostream>

#include "network/Connection.cpp"
#include "network/http/HttpHeader.cpp"


using namespace std;

int main() {
	cout << "Necronda Server 3.0" << endl << "by Lorenz Stechauner" << endl << endl;

	unsigned short PORT = 8080;

	Connection *s;
	try {
		s = new Connection();
	} catch (char *msg) {
		cout << "Unable to create socket: " << msg << endl;
		exit(1);
	}

	try {
		s->bind(PORT);
	} catch (char *msg) {
		cout << "Unable to bind socket to port " << PORT << ": " << msg << endl;
		exit(2);
	}

	try {
		s->listen(256);
	} catch (char *msg) {
		cout << "Unable to listen on socket: " << msg << endl;
		exit(3);
	}

	while (true) {
		try {
			Connection *client = s->accept();
			cout << client->getPeerAddress()->toString() << ":" << client->getPeerPort() << " <-> "
				 << client->getSocketAddress()->toString() << ":" << client->getSocketPort() << endl;
		} catch (char *msg) {
			cout << msg << endl;
			break;
		}
	}

	return 0;
}

