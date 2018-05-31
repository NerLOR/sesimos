/**
 * Necronda Web Server 3.0
 * HttpHeader.h - HttpHeader Class definition
 * Lorenz Stechauner, 2018-05-09
 */

#ifndef NECRONDA_ADDRESS
#define NECRONDA_ADDRESS

using namespace std;

class Address {
private:
	unsigned int address;

public:
	Address();

	explicit Address(string address);

	explicit Address(struct sockaddr_in *address);

	struct sockaddr_in toStruct(unsigned short port) const;

	string toString() const;

	bool isLocal();

};

#endif
