/**
 * Necronda Web Server 3.0
 * Socket.h - Socket Class definition
 * Lorenz Stechauner, 2018-05-09
 */

#ifndef NECRONDA_SOCKET
#define NECRONDA_SOCKET

#include <map>

#define CPPNET_CHUNK  16384

typedef struct {
	string privkey;
	string fullchain;
} KeyPair;

using namespace std;


class Socket {
private:
	int fd;
	SSL *ssl;
	SSL_CTX *ctx;
	bool enc;
	bool servers;
	bool clients;
	unsigned long bytesSent;
	unsigned long bytesReceived;
	long microsStart;
	long microsLast;

	void setSocketOption(int, bool);

	long send(void *buffer, int size);

	long receive(void *buffer, int size);

	long peek(void *buffer, int size);

public:
	Socket();

	explicit Socket(int filedescriptor);

	~Socket();

	void bind(Address *address, unsigned short port);

	void bind(unsigned short port);

	void listen(int count = 1);

	void connect(Address address, unsigned short port);

	Socket* accept();

	void sslHandshake();

	void sslHandshake(map<string, KeyPair> sni);

	void sslHandshake(KeyPair keypair);

	void sslHandshake(string privkey, string fullchain);

	long send(string *str);

	long send(string str);

	long send(const char *str);

	long send(const char *str, long length);

	string receive();

	string receive(long length);

	string receive(string until);

	string receive(const char *until, unsigned long strlen);

	string receive(const char *until);

	void receive(FILE *file);

	string receiveLine();

	void shutdown();

	void close();

	long getDuration();

	Address *getSocketAddress() const;

	unsigned short getSocketPort() const;

	Address *getPeerAddress() const;

	unsigned short getPeerPort() const;

	string toString() const;


	bool isServerSide();

	bool isClientSide();

	bool isSecured();


	void setReuseAddress(bool value = true);

	void setReusePort(bool value = true);

	void setSendBufferSize(int value);

	void setReceiveBufferSize(int value);

	void setMinReceiveBytes(int value);

	void setMinSendBytes(int value);

	void setSendTimeout(unsigned long ms);

	void setReceiveTimeout(unsigned long ms);


	bool getReuseAddress();

	bool getReusePort();

	int getSendBufferSize();

	int getReceiveBufferSize();

	int getMinReceiveBytes();

	int getMinSendBytes();

	long getSendTimeout();

	long getReceiveTimeout();

	unsigned long getBytesSent();

	unsigned long getBytesReceived();

	static long select(list<Socket> read, list<Socket> write, long millis);

	static long select(list<Socket> read, list<Socket> write);

	void receive(FILE *file, long size);
};

Socket operator<<(Socket sock, const char *str);

Socket operator<<(Socket sock, string str);

ostream &operator<<(ostream &str, const Socket &socket);

ostream &operator<<(ostream &str, const Socket *socket);

string operator+(string &str, const Socket &socket);

string operator+(const Socket &socket, string &str);

#endif
