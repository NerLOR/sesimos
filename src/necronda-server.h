//
// Created by lorenz on 5/17/18.
//

#include <string>

#ifndef NECRONDA_SERVER
#define NECRONDA_SERVER

#define CHUNK  16384

using namespace std;

unsigned long getMicros();

string formatTime(long micros);

string formatSize(unsigned long bytes);

string getWebRoot(string host);

string getMimeType(string path);

string getHttpDate(time_t time);

string getHttpDate();

string getHttpDate(string filename);

string getTimestamp(string path);

string getTimestamp(time_t time);

long getFileSize(string filename);


#endif
