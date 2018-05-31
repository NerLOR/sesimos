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

std::string getTimestamp(string path) {
	struct stat attrib;
	stat(path.c_str(), &attrib);
	return getTimestamp(attrib.st_ctime);
}

std::string getTimestamp(time_t time) {
	char buffer[64];
	struct tm *timeinfo = gmtime(&time);
	strftime(buffer, sizeof(buffer), "%Y%m%d%H%M%S", timeinfo);
	return string(buffer);
}

long getFileSize(string filename) {
	struct stat stat_buf;
	int rc = stat(filename.c_str(), &stat_buf);
	return rc == 0 ? stat_buf.st_size : -1;
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

std::string formatSize(unsigned long bytes) {
	char buffer[64];
	if (bytes > 0x10000000000) {
		sprintf(buffer, "%.1f TiB", (double) bytes / 0x10000000000);
	} else if (bytes > 0x40000000) {
		sprintf(buffer, "%.1f GiB", (double) bytes / 0x40000000);
	} else if (bytes > 0x100000) {
		sprintf(buffer, "%.1f MiB", (double) bytes / 0x100000);
	} else if (bytes > 0x400) {
		sprintf(buffer, "%.1f KiB", (double) bytes / 0x400);
	} else {
		sprintf(buffer, "%ld B", bytes);
	}
	return std::string(buffer);
}

string getWebRoot(string host) {
	return "/home/lorenz/Documents/Projects/Necronda-Server/necronda-server-3.0/webroot";
}



string url_decode(string url) {
	long pos = 0;
	while ((pos = url.find('+', pos + 1)) != string::npos) {
		url.replace(pos, 1, 1, ' ');
	}
	pos = 0;
	while ((pos = url.find('%', pos + 1)) != string::npos) {
		const char *num = url.substr(pos + 1, 2).c_str();
		auto c = (char) strtol(num, nullptr, 16);
		url.erase(pos, 3);
		url.insert(pos, 1, c);
	}

	return url;
}

string url_encode(string url) {
	char buff[4];
	for (long pos = 0; pos < url.length(); pos++) {
		auto c = (unsigned char) url[pos];
		if (c < ' ' || c > '~' || c == ' ' || c == '#' || c == '?' || c == '&' || c == '=' || c == '\\' || c == '%') {
			sprintf(buff, "%%%02X", c);
			url.replace(pos, 1, buff);
		}
	}
	return url;
}

string html_decode(string text) {
	return text;
}

string html_encode(string text) {
	return text;
}

string cli_encode(string text) {
	char buff[5];
	for (long pos = 0; pos < text.length(); pos++) {
		auto c = (unsigned char) text[pos];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ',' || c == '.' || c == '_' || c == '+' || c == ':' || c == '@' || c == '%' || c == '/' || c == '-')) {
			sprintf(buff, "\\%.1s", &c);
			text.replace(pos, 1, buff);
			pos++;
		}
	}
	return text;
}

string read_line(FILE* file) {
	char *line = nullptr;
	size_t len = 0;
	ssize_t read;
	if ((read = getline(&line, &len, file)) < 0) {
		return "";
	}
	string l = string(line);
	if (l[l.length()-1] == '\n') {
		l.erase(l.length()-1);
	}
	if (l[l.length()-1] == '\r') {
		l.erase(l.length()-1);
	}
	return l;
}


#include "procopen.cpp"
#include "network/Address.cpp"
#include "network/Socket.cpp"
#include "URI.cpp"
#include "network/http/HttpStatusCode.cpp"
#include "network/http/HttpHeader.cpp"
#include "network/http/HttpRequest.cpp"
#include "network/http/HttpResponse.cpp"
#include "network/http/HttpConnection.cpp"

#include "client.cpp"


long clientnum = 0;

int main() {
	cout << "Necronda Server 3.0" << endl << "by Lorenz Stechauner" << endl << endl;

	signal(SIGPIPE, SIG_IGN);

	SSL_load_error_strings();
	SSL_library_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	int ret = system("mkdir -p /var/necronda /etc/necronda /tmp/necronda; touch /var/necronda/ETags");

	if (ret != 0) {
		cout << "Unable to create server files" << endl;
		exit(1);
	}

	list<unsigned short> ports = {8080, 4443};

	list<Socket> servers = {};
	auto it = ports.begin();

	for (int i = 0; i < ports.size(); i++) {
		unsigned short port = *it;
		advance(it, 1);
		Socket server = Socket();
		servers.push_back(server);

		try {
			server.setReuseAddress(true);
			server.setReceiveTimeout(0);
			server.setSendTimeout(0);
		} catch (char *msg) {
			cout << "Unable to set socket option: " << msg << endl;
			exit(2);
		}

		try {
			server.bind(port);
		} catch (char *msg) {
			cout << "Unable to bind socket to port " << port << ": " << msg << endl;
			exit(3);
		}

		try {
			server.listen(256);
		} catch (char *msg) {
			cout << "Unable to listen on socket: " << msg << endl;
			exit(4);
		}

	}

	cout << "Ready for connections" << endl;

	while (true) {
		try {
			Socket::select(servers, {});
			for (Socket server : servers) {
				try {
					Socket *socket = server.accept();
					clientnum++;
					thread *t = new thread(client_handler, socket, clientnum, server.getSocketPort() == 4443);
				} catch (char *msg) {
					// Nothing
				}
			}
		} catch (char *msg) {
			cout << "Select: " << msg << endl;
			break;
		}
	}

	return 0;
}


