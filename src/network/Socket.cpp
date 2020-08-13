/**
 * Necronda Web Server 3.0
 * Socket.cpp - Socket Class methods
 * Lorenz Stechauner, 2018-05-09
 */


#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <utility>
#include <unistd.h>
#include <sstream>
#include <ctime>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <list>
#include <sys/stat.h>

#include "Address.h"
#include "Socket.h"
#include "http/Http.h"

using namespace std;


static void multi_ssl_init() {
    SSL_load_error_strings();
    SSL_library_init();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}


char *multi_ssl_get_error(SSL *ssl, int ret) {
    if (ret > 0) {
        return nullptr;
    }

    unsigned long ret2 = ERR_get_error();
    const char *err2 = strerror(errno);
    const char *err1 = ERR_reason_error_string(ret2);

    switch (SSL_get_error(ssl, ret)) {
        case SSL_ERROR_NONE:
            return (char *) "none";
        case SSL_ERROR_ZERO_RETURN:
            return (char *) "closed";
        case SSL_ERROR_WANT_READ:
            return (char *) "want_read";
        case SSL_ERROR_WANT_WRITE:
            return (char *) "want_write";
        case SSL_ERROR_WANT_CONNECT:
            return (char *) "want_connect";
        case SSL_ERROR_WANT_ACCEPT:
            return (char *) "want_accept";
        case SSL_ERROR_WANT_X509_LOOKUP:
            return (char *) "want_x509_lookup";
        case SSL_ERROR_SYSCALL:
            return (char *) ((ret2 == 0) ? (ret == 0) ? "protocol violation" : err2 : err1);
        case SSL_ERROR_SSL:
            return (char *) err1;
        default:
            return (char *) "unknown error";
    }
}

char *strerror_socket(int nr) {
    if (nr == EAGAIN || nr == EWOULDBLOCK) {
        return (char *) "timeout";
    } else if (nr == ECONNRESET) {
        return (char *) "closed";
    } else {
        return strerror(nr);
    }
}


Socket::Socket(int fd) {
    this->fd = fd;
    microsStart = getMicros();
    microsLast = microsStart;
    bytesSent = 0;
    bytesReceived = 0;
    enc = false;
    ssl = nullptr;
    ctx = nullptr;
    clients = false;
    servers = false;
}

Socket::Socket() {
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd == 0) {
        throw strerror(errno);
    }
    enc = false;
    microsStart = getMicros();
    microsLast = microsStart;
    bytesSent = 0;
    bytesReceived = 0;
    ssl = nullptr;
    ctx = nullptr;
    clients = false;
    servers = false;
}

int Socket::getFd() {
    return fd;
}

void Socket::setSocketOption(int option, bool value = true) {
    int val = value ? 1 : 0;

    if (::setsockopt(fd, SOL_SOCKET, option, &val, sizeof(val)) != 0) {
        throw strerror(errno);
    }
}

void Socket::bind(Address *address, unsigned short port) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY; // address.
    addr.sin_port = htons(port);

    if (::bind(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        throw strerror(errno);
    }
}

void Socket::bind(unsigned short port) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (::bind(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        throw strerror(errno);
    }
}

void Socket::listen(int num) {
    if (::listen(fd, num) != 0) {
        throw strerror(errno);
    }
}

void Socket::connect(Address, unsigned short) {

}

Socket* Socket::accept() {
    int newfd = ::accept(fd, nullptr, nullptr);
    if (newfd < 0) {
        throw strerror(errno);
    }
    Socket *socket = new Socket(newfd);
    socket->servers = true;
    return socket;
}

void Socket::close() {
    if (isSecured()) {
        //SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }

    if (::close(fd) != 0) {
        throw strerror(errno);
    }
}

Address *Socket::getPeerAddress() const {
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    getpeername(fd, (struct sockaddr *) &addr, &len);
    struct sockaddr_in *s = (struct sockaddr_in *) &addr;
    return new Address(s);
}

unsigned short Socket::getPeerPort() const {
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    getpeername(fd, (struct sockaddr *) &addr, &len);
    return ntohs(((struct sockaddr_in *) &addr)->sin_port);
}

Address *Socket::getSocketAddress() const {
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    getsockname(fd, (struct sockaddr *) &addr, &len);
    struct sockaddr_in *s = (struct sockaddr_in *) &addr;
    return new Address(s);
}

unsigned short Socket::getSocketPort() const {
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    getsockname(fd, (struct sockaddr *) &addr, &len);
    return ntohs(((struct sockaddr_in *) &addr)->sin_port);
}


void Socket::setReuseAddress(bool value) {
    setSocketOption(SO_REUSEADDR, value);
}

void Socket::setReusePort(bool value) {
    setSocketOption(SO_REUSEPORT, value);
}


string Socket::toString() const {
    return "{[Socket]" + getSocketAddress()->toString() + ":" + to_string(getSocketPort()) + "<->" +
           getPeerAddress()->toString() + ":" + to_string(getPeerPort()) + "}";
}

long Socket::send(string *str) {
    return send(str->c_str(), str->length());
}

long Socket::send(string str) {
    return send(str.c_str(), str.length());
}

long Socket::send(const char *str, long length) {
    return send((void*) str, length);
}

long Socket::send(const char *str) {
    return send(str, strlen(str));
}

Socket::~Socket() {

}

long Socket::receive(void *buffer, int size) {
    long len;
    if (isSecured()) {
        len = SSL_read(ssl, buffer,  size);
        if (len < 0) {
            throw multi_ssl_get_error(ssl, (int) len);
        }
    } else {
        len = recv(fd, buffer, (size_t) size, 0);
        if (len < 0) {
            throw strerror_socket(errno);
        }
    }
    bytesReceived += len;
    return len;
}

long Socket::peek(void *buffer, int size) {
    long len;
    if (isSecured()) {
        len = SSL_peek(ssl, buffer, size);
        if (len < 0) {
            throw multi_ssl_get_error(ssl, (int) len);
        }
    } else {
        len = recv(fd, buffer, (size_t) size, MSG_PEEK);
        if (len < 0) {
            throw strerror_socket(errno);
        }
    }
    return len;
}

long Socket::send(void *buffer, int size) {
    long len;
    if (isSecured()) {
        if (size != 0) {
            len = SSL_write(ssl, buffer, size);
            if (len <= 0) {
                throw multi_ssl_get_error(ssl, (int) len);
            }
        } else {
            len = 0;
        }
    } else {
        len = ::send(fd, buffer, (size_t) size, 0);
        if (len < 0) {
            throw strerror_socket(errno);
        }
    }
    bytesSent += len;
    return len;
}


string Socket::receive() {
    string *str = new string();

    char buffer[CPPNET_CHUNK];
    long len = 0;
    do {
        len = receive((void*) buffer, CPPNET_CHUNK);
        str->append(buffer, (unsigned) len);
    } while (len > 0 && len == CPPNET_CHUNK);

    return *str;
}

string Socket::receive(long length) {
    string *str = new string();

    char buffer[CPPNET_CHUNK];
    long len = 0;
    long reclen = 0;
    do {
        len = receive((void*) buffer, CPPNET_CHUNK);
        reclen += len;
        str->append(buffer, (unsigned) len);
    } while (reclen < length);

    return *str;
}

string Socket::receive(string until) {
    string *str = new string();

    struct pollfd ufds[1];
    ufds[0].fd = fd;
    ufds[0].events = POLLIN | POLLOUT;

    char buffer[CPPNET_CHUNK];
    long len = 0;
    do {
        len = peek((void*) buffer, CPPNET_CHUNK);
        if (len != 0) {
            string s = string(buffer, (size_t) len);
            size_t found = s.find(until);
            long l = (found != string::npos) ? found + 1 : len;
            long l2 = (found != string::npos) ? found : len;
            str->append(buffer, (unsigned) l2);
            receive((void *) buffer, (int) l);
            if (found != string::npos) {
                break;
            }
        }
        if (poll(ufds, 1, 0) < 0) {
            throw strerror_socket(errno);
        } else if ((ufds[0].revents & POLLIN) == 0) {
            if ((ufds[0].revents & POLLOUT) != 0) {
                throw (char *) "error";
            } else {
                throw (char *) "want_write";
            }
        } else if ((ufds[0].revents & POLLERR) != 0) {
            throw (char *) "error";
        } else if (ufds[0].revents & (POLLRDHUP | POLLHUP | POLLNVAL) != 0) {
            throw (char *) "closed";
        }
    } while (true);

    return *str;
}

string Socket::receive(const char *until) {
    return receive(until, (int) (strlen(until)));
}

string Socket::receive(const char *until, unsigned long strlen) {
    return receive(string(until, strlen));
}

void Socket::receive(FILE *file) {
    char buffer[CPPNET_CHUNK];
    long len = 0;
    do {
        len = receive((void*) buffer, CPPNET_CHUNK);
        fwrite(buffer, 1, CPPNET_CHUNK, file);
    } while (len > 0 && len == CPPNET_CHUNK);
}

void Socket::receive(FILE *file, long size) {
    char buffer[CPPNET_CHUNK];
    long len = 0;
    long rec = 0;
    while (size > rec) {
        len = receive((void*) buffer, (CPPNET_CHUNK > (size - rec) && size >= 0)?(size - rec):CPPNET_CHUNK);
        fwrite(buffer, 1, len, file);
        rec += len;
    }
}

string Socket::receiveLine() {
    string str = receive("\n");
    if (str.length() > 0 && str.at(str.length() - 1) == '\r') {
        str = str.substr(0, str.length() - 1);
    }
    return str;
}


long Socket::getDuration() {
    return getMicros() - microsStart;
}


void Socket::setReceiveTimeout(unsigned long ms) {
    struct timeval timeout;
    if (ms == 0) {
        timeout.tv_sec = 0;
        timeout.tv_usec = 1;
    } else {
        timeout.tv_sec = ms / 1000;
        timeout.tv_usec = (ms % 1000) * 1000;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout)) < 0) {
        throw strerror(errno);
    }
}

void Socket::setSendTimeout(unsigned long ms) {
    struct timeval timeout;
    if (ms == 0) {
        timeout.tv_sec = 0;
        timeout.tv_usec = 1;
    } else {
        timeout.tv_sec = ms / 1000;
        timeout.tv_usec = (ms % 1000) * 1000;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout)) < 0) {
        throw strerror(errno);
    }
}

bool Socket::isServerSide() {
    return servers;
}

bool Socket::isSecured() {
    return enc;
}

bool Socket::isClientSide() {
    return clients;
}

void Socket::sslHandshake(map<string, KeyPair> sni) {
    /*if (isSecured()) {
        throw (char *) "Socket already secured";
    }

    const SSL_METHOD *method;
    if (isServerSide()) {
        method = TLSv1_2_server_method();
    } else if (isClientSide()) {
        method = TLSv1_2_client_method();
    } else {
        method = TLSv1_2_method();
    }

    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4");
    SSL_CTX_set_ecdh_auto(ctx, 1);

    const char *certfile = keypair.fullchain.c_str();
    const char *keyfile = keypair.privkey.c_str();

    if (isServerSide()) {
        if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) != 1) {
            throw (char *) ERR_reason_error_string(ERR_get_error());
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1) {
            throw (char *) ERR_reason_error_string(ERR_get_error());
        }
    }

    SSL_CTX_set_tlsext_servername_callback

    this->ctx = ctx;
    this->ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    enc = true;

    while (true) {
        int ret = 0;
        if (isServerSide()) {
            ret = SSL_accept(ssl);
        } else if (isClientSide()) {
            ret = SSL_connect(ssl);
        } else {
            ret = SSL_do_handshake(ssl);
        }

        if (ret <= 0 && ((isServerSide() && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_READ) ||
                         (isClientSide() && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_WRITE))) {
            throw multi_ssl_get_error(ssl, ret);
        } else if (ret == 1) {
            break;
        }
    }*/

}

void Socket::sslHandshake() {
    sslHandshake(KeyPair{"", ""});
}

void Socket::sslHandshake(KeyPair keypair) {
    if (isSecured()) {
        throw (char *) "Socket already secured";
    }

    const SSL_METHOD *method;
    if (isServerSide()) {
        method = TLSv1_2_server_method();
    } else if (isClientSide()) {
        method = TLSv1_2_client_method();
    } else {
        method = TLSv1_2_method();
    }

    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION); // TLS1_VERSION
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4");
    SSL_CTX_set_ecdh_auto(ctx, 1);

    const char *certfile = keypair.fullchain.c_str();
    const char *keyfile = keypair.privkey.c_str();

    if (isServerSide()) {
        if (SSL_CTX_use_certificate_chain_file(ctx, certfile) != 1) {
            throw (char *) ERR_reason_error_string(ERR_get_error());
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1) {
            throw (char *) ERR_reason_error_string(ERR_get_error());
        }
    }

    this->ctx = ctx;
    this->ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    enc = true;

    while (true) {
        int ret = 0;
        if (isServerSide()) {
            ret = SSL_accept(ssl);
        } else if (isClientSide()) {
            ret = SSL_connect(ssl);
        } else {
            ret = SSL_do_handshake(ssl);
        }

        if (ret <= 0 && ((isServerSide() && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_READ) ||
                         (isClientSide() && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_WRITE))) {
            throw multi_ssl_get_error(ssl, ret);
        } else if (ret == 1) {
            break;
        }
    }

}

void Socket::sslHandshake(string privkey, string fullchain) {
    sslHandshake(KeyPair{std::move(privkey), std::move(fullchain)});
}

long Socket::select(list<Socket> read, list<Socket> write, long millis) {
    fd_set readfd, writefd;
    int maxfd = 0;
    FD_ZERO(&readfd);
    FD_ZERO(&writefd);

    for (Socket s : read) {
        if (s.fd > maxfd) {
            maxfd = s.fd;
        }
        FD_SET(s.fd, &readfd);
    }

    for (Socket s : write) {
        if (s.fd > maxfd) {
            maxfd = s.fd;
        }
        FD_SET(s.fd, &writefd);
    }

    struct timeval *tv = new struct timeval;
    if (millis < 0) {
        tv = nullptr;
    } else if (millis == 0) {
        tv->tv_sec = 0;
        tv->tv_usec = 1;
    } else {
        tv->tv_sec = millis / 1000;
        tv->tv_usec = (millis % 1000) * 1000;
    }

    int ret = ::select(maxfd + 1, &readfd, &writefd, nullptr, tv);
    if (ret < 0) {
        throw (char *) strerror(errno);
    }
    return ret;
}

long Socket::select(list<Socket> read, list<Socket> write) {
    Socket::select(std::move(read), std::move(write), -1);
}

unsigned long Socket::getBytesSent() {
    return bytesSent;
}

unsigned long Socket::getBytesReceived() {
    return bytesReceived;
}


ostream &operator<<(ostream &str, const Socket &socket) {
    return str << socket.toString();
}

ostream &operator<<(ostream &str, const Socket *socket) {
    return str << socket->toString();
}

string operator+(string &str, const Socket &socket) {
    return str + socket.toString();
}

string operator+(const Socket &socket, string &str) {
    return socket.toString() + str;
}




