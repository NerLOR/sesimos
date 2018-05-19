/**
 * Necronda Web Server 3.0
 * client.cpp - Client and Connection handler
 * Lorenz Stechauner, 2018-05-16
 */


#include <string>
#include <iostream>
#include <zlib.h>
#include <cassert>
#include "network/Socket.h"
#include "network/http/HttpRequest.h"
#include "network/http/HttpConnection.h"
#include "necronda-server.h"
#include "network/http/HttpStatusCode.h"
#include "Path.h"


/**
 * Writes log messages to the console
 * @param prefix The connection prefix
 * @param string The string to be written
 */
void log(const char *prefix, const string &string) {
	printf("%s%s\r\n", prefix, string.c_str());
	flush(cout);
}

/**
 * Handles (keep-alive) HTTP connections
 * @param prefix The connection prefix
 * @param socket The socket
 * @param id The client ID
 * @param num The Connection Number in the client
 * @return Should the server wait for another header?
 */
bool connection_handler(const char *prefix, Socket socket, long id, long num) {
	bool error = false;
	try {
		HttpConnection req(socket);
		try {
			if (req.isExistingField("Connection") && req.getField("Connection") == "keep-alive") {
				req.setField("Connection", "keep-alive");
				req.setField("Keep-Alive", "timeout=30, max=200");
			} else {
				req.setField("Connection", "close");
				error = true;
			}

			if (!req.isExistingField("Host")) {
				req.respond(400);
			} else {
				string host = req.getField("Host");

				string str = string(prefix);
				unsigned long pos = str.find('[', 8);
				string n = str.substr(0, 8) + host + str.substr(pos - 1, str.length() - pos + 1);

				char buffer[256];
				sprintf(buffer, "%s", n.c_str());
				prefix = buffer;

				Path path = Path(getWebRoot(host), req.getPath());
				log(prefix, req.getMethod() + " " + req.getPath());

				FILE *file = path.openFile();

				if (file == nullptr) {
					req.setField("Cache-Control", "public, max-age=60");
					req.respond(404);
				} else {
					string type = path.getFileType();

					if (type.find("inode/") == 0) {
						req.respond(403);
					} else {
						req.setField("Content-Type", type);
						req.setField("Last-Modified", getHttpDate(path.getAbsolutePath()));

						bool invalidMethod = false;

						if (path.isStatic()) {
							req.setField("Accept-Ranges", "bytes");
							req.setField("Cache-Control", "public, max-age=10");
							req.setField("Allow", "GET");
							if (req.getMethod() != "GET") {
								invalidMethod = true;
							}
						} else {
							req.setField("Accept-Ranges", "none");
							req.setField("Cache-Control", "private, no-cache");
							req.setField("Allow", "GET, POST, PUT");
							if (req.getMethod() != "GET" && req.getMethod() != "POST" && req.getMethod() != "PUT") {
								invalidMethod = true;
							}
						}

						if (invalidMethod) {
							req.respond(405);
						} else {

							bool compress = type.find("text/") == 0 && req.isExistingField("Accept-Encoding") &&
											req.getField("Accept-Encoding").find("deflate") != string::npos;

							if (req.isExistingField("Range")) {
								string range = req.getField("Range");
								if (range.find("bytes=") != 0 || !path.isStatic()) {
									req.respond(416);
								} else {
									fseek(file, 0L, SEEK_END);
									long len = ftell(file);
									fseek(file, 0L, SEEK_SET);
									long p = range.find('-');
									if (p == string::npos) {
										req.respond(416);
									} else {
										string part1 = range.substr(6, p - 6);
										string part2 = range.substr(p + 1, range.length() - p - 1);
										long num1 = stol(part1, nullptr, 10);
										long num2 = len - 1;
										if (!part2.empty()) {
											num2 = stol(part2, nullptr, 10);
										}
										if (num1 < 0 || num1 >= len || num2 < 0 || num2 >= len) {
											req.respond(416);
										} else {
											req.setField("Content-Range", (string) "bytes " + to_string(num1) + "-" + to_string(num2) + "/" + to_string(len));
											req.respond(206, file, compress, num1, num2);
										}
									}
								}
							} else {
								req.respond(200, file, compress);
							}
						}
					}
					fclose(file);
				}
			}
			HttpStatusCode status = req.getStatusCode();
			log(prefix, to_string(status.code) + " " + status.message + " (" + formatTime(req.getDuration()) + ")");
		} catch (char *msg) {
			HttpStatusCode status = req.getStatusCode();
			log(prefix, to_string(status.code) + " " + status.message + " (" + formatTime(req.getDuration()) + ")");
			try {
				if (msg == "timeout") {
					log(prefix, "Timeout!");
					req.setField("Connection", "close");
					req.respond(408);
					error = true;
				} else if (msg == "Invalid path") {
					log(prefix, "Timeout!");
					req.respond(400);
				} else {
					log(prefix, (string) "Unable to receive from socket: " + msg);
					error = true;
				}
			} catch (char *msg2) {

			}
		}
	} catch (char *msg) {
		try {
			if (msg == "Malformed header") {
				log(prefix, "Unable to parse header: Malformed header");
				socket << "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
				error = true;
			} else if (msg == "timeout") {
				log(prefix, "Timeout!");
				socket << "HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n";
				error = true;
			} else {
				log(prefix, (string) "Unable to receive from socket: " + msg);
				error = true;
			}
		} catch (char *msg2) {

		}
	}
	return !error;
}

/**
 * Handles HTTP clients
 * @param socket The socket
 * @param id The client ID
 */
void client_handler(Socket *socket, long id) {
	const char *prefix;
	{
		char const *col1;
		char const *col2 = "\x1B[0m";
		int group = (int) (id % 6);
		if (group == 0) {
			col1 = "\x1B[1;31m";
		} else if (group == 1) {
			col1 = "\x1B[1;32m";
		} else if (group == 2) {
			col1 = "\x1B[1;34m";
		} else if (group == 3) {
			col1 = "\x1B[1;33m";
		} else if (group == 4) {
			col1 = "\x1B[1;35m";
		} else {
			col1 = "\x1B[1;36m";
		}
		string *a = new string((string)
									   col1 + "[" + socket->getSocketAddress()->toString() + "][" +
							   to_string(socket->getSocketPort()) + "]" +
							   "[" + socket->getPeerAddress()->toString() + "][" + to_string(socket->getPeerPort()) +
							   "]" + col2 + " ");
		prefix = a->c_str();
	}

	log(prefix, "Connection established");

	bool err = false;
	try {
		socket->setReceiveTimeout(30000);
		socket->setSendTimeout(30000);
	} catch (char *msg) {
		log(prefix, (string) "Unable to set timeout on socket: " + msg);
		err = true;
	}

	try {
		if (socket->getSocketPort() == 443) {
			socket->sslHandshake("/home/lorenz/Documents/Projects/Necronda-Server/necronda-server-3.0/privkey.pem",
								 "/home/lorenz/Documents/Projects/Necronda-Server/necronda-server-3.0/fullchain.pem");
		}
	} catch (char *msg) {
		log(prefix, (string) "Unable to perform handhsake: " + msg);
		err = true;
	}

	long reqnum = 0;
	if (!err) {
		while (connection_handler(prefix, *socket, id, ++reqnum));
		reqnum--;
	}

	log(prefix, "Connection terminated (#:" + to_string(reqnum) + ", R:, S:, T: " + formatTime(socket->getDuration()) + ")");
	socket->close();
}


