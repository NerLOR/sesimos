/**
 * Necronda Web Server 3.0
 * necronda-server.cpp - Main Executable
 * Lorenz Stechauner, 2018-05-09
 */


#include "necronda-server.h"
#include <magic.h>
#include <iostream>
#include <thread>
#include <sys/time.h>
#include <sys/stat.h>
#include <bits/signum.h>
#include <csignal>


using namespace std;



/**
 * Returns UNIX time in microseconds
 * @return UNIX time [µs]
 */
unsigned long getMicros() {
	struct timeval tv;
	gettimeofday(&tv, nullptr);
	return (unsigned long) (1000000 * tv.tv_sec + tv.tv_usec);
}


string getMimeType(string path) {

	unsigned long pos = path.find_last_of('.');
	string ext;
	if (pos != string::npos) {
		ext = path.substr(pos + 1, path.length() - pos);
	}

	magic_t magic = magic_open(MAGIC_MIME_TYPE);
	magic_load(magic, "/usr/share/misc/magic.mgc");
	string type = magic_file(magic, path.c_str());
	magic_setflags(magic, MAGIC_MIME_ENCODING);
	string charset = magic_file(magic, path.c_str());

	if (type == "text/plain") {
		if (ext == "css") {
			type = "text/css";
		} else if (ext == "js") {
			type = "text/javascript";
		}
	}

	magic_close(magic);

	return type + "; charset=" + charset;
}

/**
 *  Sun, 06 Nov 1994 08:49:37 GMT
 * @return
 */
string getHttpDate() {
	time_t rawtime;
	time(&rawtime);
	return getHttpDate(rawtime);
}

string getHttpDate(string filename) {
	struct stat attrib;
	stat(filename.c_str(), &attrib);
	return getHttpDate(attrib.st_ctime);
}

string getHttpDate(time_t time) {
	char buffer[64];
	struct tm *timeinfo = gmtime(&time);
	strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", timeinfo);
	return string(buffer);
}

/**
 * Returns a formatted time string
 * @param micros Delta time to be formatted
 * @return A formatted time string
 */
std::string formatTime(long micros) {
	char buffer[64];
	if (micros < 1000) {
		sprintf(buffer, "%.3f ms", micros / 1000.0);
	} else if (micros < 10000) {
		sprintf(buffer, "%.2f ms", micros / 1000.0);
	} else if (micros < 100000) {
		sprintf(buffer, "%.1f ms", micros / 1000.0);
	} else if (micros < 1000000) {
		sprintf(buffer, "%.0f ms", micros / 1000.0);
	} else {
		sprintf(buffer, "%.1f s", micros / 1000000.0);
	}
	return std::string(buffer);
}

string getWebRoot(string host) {
	return "/home/lorenz/Documents/Projects/Necronda-Server/necronda-server-3.0/webroot";
}


#include "network/Address.cpp"
#include "network/Socket.cpp"
#include "Path.cpp"
#include "network/http/HttpStatusCode.cpp"
#include "network/http/HttpHeader.cpp"
#include "network/http/HttpRequest.cpp"
#include "network/http/HttpResponse.cpp"
#include "network/http/HttpConnection.cpp"

#include "client.cpp"


long clientnum = 0;

int main() {

	SSL_load_error_strings();
	SSL_library_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	signal(SIGPIPE, SIG_IGN);

	cout << "Necronda Server 3.0" << endl << "by Lorenz Stechauner" << endl << endl;

	unsigned short PORT = 443;

	Socket *s;
	try {
		s = new Socket();
	} catch (char *msg) {
		cout << "Unable to create socket: " << msg << endl;
		exit(1);
	}

	try {
		s->setReuseAddress(true);
	} catch (char *msg) {
		cout << "Unable to set socket option: " << msg << endl;
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
			Socket *socket = s->accept();
			clientnum++;
			thread *t = new thread(client_handler, socket, clientnum);
		} catch (char *msg) {
			cout << msg << endl;
			break;
		}
	}

	return 0;
}


