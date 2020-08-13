#include <utility>

#include <utility>

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
#include <fcntl.h>
#include <sstream>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "network/Socket.h"
#include "network/http/HttpRequest.h"
#include "network/http/HttpConnection.h"
#include "necronda-server.h"
#include "network/http/HttpStatusCode.h"
#include "URI.h"
#include "procopen.h"
#include "network/Address.h"


typedef struct {
    string host;
    string cc;
    string country;
    string prov;
    string provname;
    string city;
    string timezone;
    string localdate;
} IpAddressInfo;


void log_to_file(const char *prefix, const string &str, string host) {
    //FILE *file = fopen((getWebRoot(std::move(host)) + ".access.log").c_str(), "a");
    //fprintf(file, "%s%s\r\n", prefix, str.c_str());
    //fflush(file);
    //fclose(file);
}

void log_error_to_file(const char *prefix, const string &str, string host) {
    log_to_file(prefix, "\x1B[1;31m" + str + "\x1B[0m", std::move(host));
}

/**
 * Writes log messages to the console
 * @param prefix The connection prefix
 * @param str The string to be written
 */
void log(const char *prefix, const string &str) {
    printf("%s%s\r\n", prefix, str.c_str());
    flush(cout);
}

void log_error(const char *prefix, const string &str) {
    log(prefix, "\x1B[1;31m" + str + "\x1B[0m");
}

void php_error_handler(const char *prefix, FILE *stderr) {
    string line;
    while (!(line = read_line(stderr)).empty()) {
        log_error(prefix, line);
    }
    fclose(stderr);
}

IpAddressInfo get_ip_address_info(Address* addr) {
    FILE *name = popen(("/opt/ipinfo/ipinfo.py " + addr->toString()).c_str(), "r");
    char hostbuffer[1024];
    memset(hostbuffer, 0, 1024);
    size_t size = fread(hostbuffer, 1, 1024, name);
    istringstream buffer(hostbuffer);
    string line;

    IpAddressInfo info;
    int num = 0;
    while (std::getline(buffer, line)) {
        switch (num) {
            case 0: info.host = line; break;
            case 1: info.cc = line; break;
            case 2: info.country = line; break;
            case 3: info.prov = line; break;
            case 4: info.provname = line; break;
            case 5: info.city = line; break;
            case 6: info.timezone = line; break;
            case 7: info.localdate = line; break;
        }
        num++;
    }
    return info;
}

string get_os_info(int fd) {
    struct tcp_info ti;
    socklen_t tisize = sizeof(ti);
    getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &tisize);

    int ttl;
    socklen_t ttlsize = sizeof(ttl);
    getsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, &ttlsize);

    return "win_size=" + to_string(ti.tcpi_rcv_space) + ", ttl=" + to_string(ttl);
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

#include <iostream>
#include <wait.h>
#include <thread>


long getPosition(std::string str, char c, int occurence) {
    int tempOccur = 0;
    int num = 0;
    for (auto it : str) {
        num++;
        if (it == c) {
            if (++tempOccur == occurence) {
                return num;
            }
        }
    }

    return -1;
}

/**
 * Handles (keep-alive) HTTP connections
 * @param prefix The connection prefix
 * @param socket The socket
 * @param id The client ID
 * @param num The Connection Number in the client
 * @return Should the server wait for another header?
 */
bool connection_handler(const char *preprefix, const char *col1, const char *col2, Socket *socket, long id, long num, IpAddressInfo *info) {
    bool error = false;
    char buffer[1024];
    char *prefix = (char *) preprefix;
    try {
        HttpConnection req(socket);
        try {
            if (req.isExistingField("Connection") && req.getField("Connection") == "keep-alive") {
                req.setField("Connection", "keep-alive");
                req.setField("Keep-Alive", "timeout=60, max=100");
            } else {
                req.setField("Connection", "close");
                error = true;
            }

            string host = "";

            if (!req.isExistingField("Host")) {
                req.respond(400);
            } else {
                host = req.getField("Host");
                long pos = host.find(':');
                if (pos != string::npos) {
                    host.erase(pos, host.length() - pos);
                }

                /*FILE *name = popen(("dig @8.8.8.8 +time=1 -x " + socket->getPeerAddress()->toString() +
                                    " | grep -oP \"^[^;].*\\t\\K([^ ]*)\\w\"").c_str(), "r");
                char hostbuffer[1024];
                memset(hostbuffer, 0, 1024);
                size_t size = fread(hostbuffer, 1, 1024, name);
                hostbuffer[size - 1] = 0; // remove \n
                if (size <= 1) {
                    sprintf(hostbuffer, "%s", socket->getPeerAddress()->toString().c_str());
                }*/

                sprintf(buffer, "[\x1B[1m%s\x1B[0m][%i]%s[%s][%i]%s ", host.c_str(), socket->getSocketPort(), col1,
                        info->host.c_str(), socket->getPeerPort(), col2);
                prefix = buffer;

                log(prefix, "\x1B[1m" + req.getMethod() + " " + req.getPath() + "\x1B[0m");
                log_to_file(prefix, "\x1B[1m" + req.getMethod() + " " + req.getPath() + "\x1B[0m", host);

                bool noRedirect = req.getPath().find("/.well-known/") == 0 || (req.getPath().find("/files/") == 0);

                bool redir = true;
                if (!noRedirect) {
                    if (getWebRoot(host).empty()) {
                        req.redirect(303, "https://www.necronda.net" + req.getPath());
                    } else if (socket->getSocketPort() != 443) {
                        req.redirect(302, "https://" + host + req.getPath());
                    } else {
                        redir = false;
                    }
                } else {
                    redir = false;
                }

                URI path = URI(getWebRoot(host), req.getPath());
                pid_t childpid = 0;

                if (redir) {

                } else if (!path.getNewPath().empty() && req.getMethod() != "POST") {
                    req.redirect(303, path.getNewPath());
                } else {
                    FILE *file = path.openFile();
                    if (file == nullptr) {
                        req.setField("Cache-Control", "public, max-age=60");
                        req.respond(404);
                    } else {
                        string type = path.getFileType();

                        if (type.find("inode/") == 0) {
                            req.respond(403);
                        } else if (path.getRelativeFilePath().find("/.") != string::npos && !noRedirect) {
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
                                if (type.find("text/") == 0) {
                                    req.setField("Cache-Control", "public, max-age=3600");
                                } else {
                                    req.setField("Cache-Control", "public, max-age=86400");
                                }
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
                            }

                            if (invalidMethod) {
                                req.respond(405);
                            } else if (etag) {
                                req.respond(304);
                            } else {
                                int statuscode = 0;
                                if (!path.isStatic()) {
                                    string cmd = (string) "env -i" +
                                                 " REDIRECT_STATUS=" + cli_encode("CGI") +
                                                 " DOCUMENT_ROOT=" + cli_encode(getWebRoot(host)) +
                                                 " " + req.cgiExport() +
                                                 (req.isExistingField("Content-Length") ? " CONTENT_LENGTH=" +
                                                                                          cli_encode(req.getField(
                                                                                                  "Content-Length"))
                                                                                        : "") +
                                                 (req.isExistingField("Content-Type") ? " CONTENT_TYPE=" + cli_encode(
                                                         req.getField("Content-Type")) : "") +
                                                 ((socket->isSecured()) ? " HTTPS=on" : "") +
                                                 " PATH_INFO=" + cli_encode(path.getFilePathInfo()) +
                                                 " PATH_TRANSLATED=" + cli_encode(path.getAbsolutePath()) +
                                                 " QUERY_STRING=" + cli_encode(path.getQuery()) +
                                                 " REMOTE_ADDR=" + cli_encode(socket->getPeerAddress()->toString()) +
                                                 " REMOTE_HOST=" + cli_encode(info->host) +
                                                 " REMOTE_PORT=" + cli_encode(to_string(socket->getPeerPort())) +
                                                 " REQUEST_METHOD=" + cli_encode(req.getMethod()) +
                                                 " REQUEST_URI=" + cli_encode(req.getPath()) +
                                                 " SCRIPT_FILENAME=" + cli_encode(path.getFilePath()) +
                                                 " SCRIPT_NAME=" + cli_encode(path.getRelativePath()) +
                                                 " SERVER_ADMIN=" + cli_encode("lorenz.stechauner@gmail.com") +
                                                 " SERVER_NAME=" + cli_encode(host) +
                                                 " SERVER_PORT=" + cli_encode(to_string(socket->getSocketPort())) +
                                                 " SERVER_SOFTWARE=" + cli_encode("Necronda 3.0") +
                                                 " SERVER_PROTOCOL=" + cli_encode("HTTP/1.1") +
                                                 " GATEWAY_INTERFACE=" + cli_encode("CGI/1.1") +
                                                 " /usr/bin/php-cgi";

                                    stds pipes = procopen(cmd.c_str());
                                    childpid = pipes.pid;

                                    long len = req.isExistingField("Content-Length") ? strtol(req.getField("Content-Length").c_str(), nullptr, 10) : (req.getMethod() == "POST" || req.getMethod() == "PUT")?-1:0;
                                    socket->receive(pipes.stdin, len);
                                    fclose(pipes.stdin);

                                    thread *t = new thread(php_error_handler, prefix, pipes.stderr);

                                    string line;
                                    while (!(line = read_line(pipes.stdout)).empty()) {
                                        long pos = line.find(':');
                                        string index = line.substr(0, pos);
                                        string data = line.substr(pos + 1, line.length() - pos);

                                        while (index[0] == ' ') index.erase(index.begin() + 0);
                                        while (index[index.length() - 1] == ' ') index.erase(index.end() - 1);
                                        while (data[0] == ' ') data.erase(data.begin() + 0);
                                        while (data[data.length() - 1] == ' ') data.erase(data.end() - 1);

                                        if (index == "Status") {
                                            statuscode = (int) strtol(data.substr(0, 3).c_str(), nullptr, 10);
                                        } else {
                                            if (index == "Location" && statuscode == 0) {
                                                statuscode = 303;
                                            } else if (index == "Content-Type") {
                                                type = data;
                                            }
                                            req.setField(index, data);
                                        }
                                    }

                                    fclose(file);
                                    int c = fgetc(pipes.stdout);
                                    if (c == -1) {
                                        // No Data -> Error
                                        req.respond((statuscode == 0) ? 500 : statuscode);
                                        statuscode = -1;
                                    } else {
                                        ungetc(c, pipes.stdout);
                                    }
                                    file = pipes.stdout;
                                }

                                if (statuscode != -1) {
                                    statuscode = (statuscode == 0) ? 200 : statuscode;

                                    bool compress = /*path.isStatic() &&*/ type.find("text/") == 0 &&
                                                                           req.isExistingField("Accept-Encoding") &&
                                                                           req.getField("Accept-Encoding").find(
                                                                                   "deflate") != string::npos;

                                    if (compress) {
                                        req.setField("Accept-Ranges", "none");
                                    }

                                    if (compress && req.isExistingField("Range")) {
                                        req.respond(416);
                                    } else if (req.isExistingField("Range")) {
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
                                        req.respond(statuscode, file, compress);
                                    }
                                }
                            }
                        }
                        fclose(file);
                        if (childpid > 0) {
                            waitpid(childpid, nullptr, 0);
                        }
                    }
                }
            }
            HttpStatusCode status = req.getStatusCode();
            int code = status.code;
            string color = "";
            string comment = "";
            if ((code >= 200 && code < 300) || code == 304) {
                color = "\x1B[1;32m"; // Success (Cached): Green
            } else if (code >= 100 && code < 200) {
                color = "\x1B[1;93m"; // Continue: Yellow
            } else if (code >= 300 && code < 400) {
                color = "\x1B[1;93m"; // Redirect: Yellow
                comment = " -> " +
                          (req.isExistingResponseField("Location") ? req.getResponseField("Location") : "<invalid>");
            } else if (code >= 400 && code < 500) {
                color = "\x1B[1;31m"; // Client Error: Red
                //comment = " -> " + req.getPath();
            } else if (code >= 500 & code < 600) {
                color = "\x1B[1;31m"; // Server Error: Red
                //comment = " -> " + req.getPath();
            }
            string msg = color + to_string(status.code) + " " + status.message + comment + " (" + formatTime(req.getDuration()) + ")\x1B[0m";
            log(prefix, msg);
            if (!host.empty()) {
                log_to_file(prefix, msg, host);
            }
        } catch (char *msg) {
            HttpStatusCode status = req.getStatusCode();
            log(prefix, to_string(status.code) + " " + status.message + " (" + formatTime(req.getDuration()) + ")");
            try {
                if (strncmp(msg, "timeout", strlen(msg)) == 0) {
                    log(prefix, "Timeout!");
                    req.setField("Connection", "close");
                    req.respond(408);
                    error = true;
                } else if (strncmp(msg, "Invalid path", strlen(msg)) == 0) {
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
    char const *col1;
    char const *col2 = "\x1B[0m";
    IpAddressInfo info = get_ip_address_info(socket->getPeerAddress());
    auto os = get_os_info(socket->getFd());
    {
        auto group = (int) (id % 6);
        if (group == 0) {
            col1 = "\x1B[0;31m"; // Red
        } else if (group == 1) {
            col1 = "\x1B[0;32m"; // Green
        } else if (group == 2) {
            col1 = "\x1B[0;34m"; // Blue
        } else if (group == 3) {
            col1 = "\x1B[0;33m"; // Yellow
        } else if (group == 4) {
            col1 = "\x1B[0;35m"; // Magenta
        } else {
            col1 = "\x1B[0;36m"; // Cyan
        }

        string *a = new string("[" + socket->getSocketAddress()->toString() + "][" +
                               to_string(socket->getSocketPort()) + "]" + col1 +
                               "[" + info.host + "][" + to_string(socket->getPeerPort()) +
                               "]" + col2 + " ");
        prefix = a->c_str();
    }

    log(prefix, "Connection established");
    log(prefix, string("Host: ") + info.host + " (" + socket->getPeerAddress()->toString() + ")");
    log(prefix, string("OS: ") + os);
    log(prefix, string("Location: ") + info.cc + "/" + info.country + ", " + info.prov + "/" + info.provname + ", " + info.city);
    log(prefix, string("Local Date: ") + info.localdate + " (" + info.timezone + ")");


    bool err = false;
    try {
        socket->setReceiveTimeout(60000);
        socket->setSendTimeout(60000);
    } catch (char *msg) {
        log(prefix, (string) "Unable to set timeout on socket: " + msg);
        err = true;
    }

    try {
        if (ssl) {
            //socket->sslHandshake("/home/lorenz/Documents/Projects/Necronda-Server/necronda-server-3.0/privkey.pem",
            //                     "/home/lorenz/Documents/Projects/Necronda-Server/necronda-server-3.0/fullchain.pem");
            socket->sslHandshake("/cert/necronda.net/privkey.pem",
                                 "/cert/necronda.net/fullchain.pem");
        }
    } catch (char *msg) {
        log(prefix, (string) "Unable to perform handshake: " + msg);
        err = true;
    }

    long reqnum = 0;
    if (!err) {
        while (connection_handler(prefix, col1, col2, socket, id, ++reqnum, &info));
        reqnum--;
    }

    log(prefix,
        "Connection terminated (#:" + to_string(reqnum) + ", R: " + formatSize(socket->getBytesReceived()) + ", S: " +
        formatSize(socket->getBytesSent()) + ", T: " + formatTime(socket->getDuration()) + ")");
    socket->close();
}


