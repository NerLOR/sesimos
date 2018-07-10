

#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include "Address.h"

using namespace std;


Address::Address() {

}

Address::Address(string addr) {
	// TODO
}

Address::Address(struct sockaddr_in *addr) {
	address = ntohl(addr->sin_addr.s_addr);
}


struct sockaddr_in Address::toStruct(unsigned short port)const {
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(address);
	addr.sin_port = htons(port);
	return addr;
}



string Address::toString() const {
	struct sockaddr_in addr = toStruct(0);
	struct in_addr ipAddr = addr.sin_addr;
	return inet_ntoa(ipAddr);
}

bool Address::isLocal() {
	string a = toString();
	return a.find("127.0.0.") == 0;
}


ostream& operator<<(ostream &str, const Address &addr) {
	return str << addr.toString();
}

string operator+(string &str, const Address &addr) {
	return str + addr.toString();
}

string operator+(string &str, const Address *addr) {
	return str + addr->toString();
}

string operator+(const Address &addr, string &str) {
	return addr.toString() + str;
}

string operator+(const Address *addr, string &str) {
	return addr->toString() + str;
}



