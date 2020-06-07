//
// Created by lorenz on 7/10/18.
//

#ifndef CPPNET_HTTP_H
#define CPPNET_HTTP_H

#include <ctime>
#include <string>

using namespace std;

unsigned long getMicros();

string getHttpDate(time_t time);

string getHttpDate();

string getHttpDate(string filename);


#endif //CPPNET_HTTP_H
