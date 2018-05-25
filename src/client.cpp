/**
 * Necronda Web Server 3.0
 * client.cpp - Client and Connection handler
 * Lorenz Stechauner, 2018-05-16
 */


#include <string>
#include <iostream>
#include <zlib.h>
#include <cassert>
#include <fstream>
#include <openssl/md5.h>
#include <cstring>

#include "network/Socket.h"
#include "network/http/HttpRequest.h"
#include "network/http/HttpConnection.h"
#include "necronda-server.h"
#include "network/http/HttpStatusCode.h"
#include "URI.h"


/**
 * Writes log messages to the console
 * @param prefix The connection prefix
 * @param string The string to be written
 */
void log(const char *prefix, const string &string) {
	printf("%s%s\r\n", prefix, string.c_str());
	flush(cout);
}

string getETag(string filename) {
	ifstream etags = ifstream("/var/necronda/ETags");

	ifstream a = ifstream();
	string line;
	int index = 0;
	int i = 0;
	string timestamp = getTimestamp(filename);
	long size = getFileSize(filename);
	while (getline(etags, line)) {
		i++;
		if (line == filename) {
			index = i;
			break;
		}
		long p1 = line.find(':');
		if (p1 == string::npos) continue;
		long p2 = line.find(':', (unsigned) p1 + 1);
		if (p2 == string::npos) continue;
		long p3 = line.find(':', (unsigned) p2 + 1);
		if (p3 == string::npos) continue;
		string FILENAME = line.substr(0, (unsigned) p1);
		string HASH = line.substr((unsigned) p1 + 1, (unsigned) (p2 - p1));
		string TIMESTAMP = line.substr((unsigned) p2 + 1, (unsigned) (p3 - p2));
		long SIZE = strtol(line.substr((unsigned) p3 + 1, line.length() - p3).c_str(), nullptr, 10);
		if (FILENAME == filename) {
			index = i;
			if (timestamp != TIMESTAMP || size != SIZE) {
				break;
			} else {
				etags.close();
				return HASH;
			}
		}
	}
	etags.close();

	MD5_CTX mdContext;
	MD5_Init(&mdContext);
	size_t bytes;
	char buffer[4096];
	FILE *file = fopen(filename.c_str(), "rb");
	if (file == nullptr) {
		throw (char *) "Invalid file";
	}
	while ((bytes = fread(buffer, 1, 4096, file)) != 0) {
		MD5_Update(&mdContext, buffer, bytes);
	}
	fclose(file);
	unsigned char md[16];
	MD5_Final(md, &mdContext);
	char md5buff[32];
	for (int i = 0; i < 16; i++) {
		sprintf(md5buff + i * 2, "%02x", md[i]);
	}
	string md5 = string(md5buff);

	if (index == 0) {
		char buff[256];
		sprintf(buff, "%s:%s:%s:%ld\n", filename.c_str(), md5.c_str(), timestamp.c_str(), size);
		FILE *f = fopen("/var/necronda/ETags", "a");
		if (f == nullptr) {
			throw (char *) strerror(errno);
		}
		fseek(f, 0, SEEK_END);
		fwrite(buff, 1, strlen(buff), f);
		fflush(f);
		fclose(f);
	} else {

	}

	return md5;
}

/**
 * Handles (keep-alive) HTTP connections
 * @param prefix The connection prefix
 * @param socket The socket
 * @param id The client ID
 * @param num The Connection Number in the client
 * @return Should the server wait for another header?
 */
bool connection_handler(const char *prefix, Socket *socket, long id, long num) {
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

				URI path = URI(getWebRoot(host), req.getPath());
				log(prefix, req.getMethod() + " " + req.getPath());

				FILE *file = path.openFile();

				if (!path.getNewPath().empty()) {
					req.redirect(302, path.getNewPath());
				} else {

					if (file == nullptr) {
						req.setField("Cache-Control", "public, max-age=60");
						req.respond(404);
					} else {
						string type = path.getFileType();

						if (type.find("inode/") == 0) {
							req.respond(403);
						} else {
							req.setField("Content-Type", type);
							req.setField("Last-Modified", getHttpDate(path.getFilePath()));

							bool invalidMethod = false;
							bool etag = false;

							if (path.isStatic()) {
								string hash = getETag(path.getFilePath());
								req.setField("ETag", hash);
								req.setField("Accept-Ranges", "bytes");
								req.setField("Cache-Control", "public, max-age=30");
								req.setField("Allow", "GET");
								if (req.getMethod() != "GET") {
									invalidMethod = true;
								}
								if (req.isExistingField("If-None-Match") && req.getField("If-None-Match") == hash) {
									etag = true;
								}
							} else {
								req.setField("Accept-Ranges", "none");
								req.setField("Cache-Control", "private, no-cache");
								req.setField("Allow", "GET, POST, PUT");
								if (req.getMethod() != "GET" && req.getMethod() != "POST" && req.getMethod() != "PUT") {
									invalidMethod = true;
								}
								system("php");
							}

							if (invalidMethod) {
								req.respond(405);
							} else if (etag) {
								req.respond(304);
							} else {

								bool compress = type.find("text/") == 0 && req.isExistingField("Accept-Encoding") &&
												req.getField("Accept-Encoding").find("deflate") != string::npos;

								if (compress) {
									req.setField("Accept-Ranges", "none");
								}

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
											string part1 = range.substr(6, (unsigned long) (p - 6));
											string part2 = range.substr((unsigned long) (p + 1),
																		range.length() - p - 1);
											long num1 = stol(part1, nullptr, 10);
											long num2 = len - 1;
											if (!part2.empty()) {
												num2 = stol(part2, nullptr, 10);
											}
											if (num1 < 0 || num1 >= len || num2 < 0 || num2 >= len) {
												req.respond(416);
											} else {
												req.setField("Content-Range",
															 (string) "bytes " + to_string(num1) + "-" +
															 to_string(num2) +
															 "/" + to_string(len));
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
					req.setField("Connection", "close");
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
				socket->send("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
				error = true;
			} else if (msg == "timeout") {
				log(prefix, "Timeout!");
				socket->send("HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n");
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
void client_handler(Socket *socket, long id, bool ssl) {
	const char *prefix;
	{
		char const *col1;
		char const *col2 = "\x1B[0m";
		auto group = (int) (id % 6);
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
		if (ssl) {
			socket->sslHandshake("/home/lorenz/Documents/Projects/Necronda-Server/necronda-server-3.0/privkey.pem",
								 "/home/lorenz/Documents/Projects/Necronda-Server/necronda-server-3.0/fullchain.pem");
		}
	} catch (char *msg) {
		log(prefix, (string) "Unable to perform handshake: " + msg);
		err = true;
	}

	long reqnum = 0;
	if (!err) {
		while (connection_handler(prefix, socket, id, ++reqnum));
		reqnum--;
	}

	log(prefix,
		"Connection terminated (#:" + to_string(reqnum) + ", R: " + formatSize(socket->getBytesReceived()) + ", S: " +
		formatSize(socket->getBytesSent()) + ", T: " + formatTime(socket->getDuration()) + ")");
	socket->close();
}


