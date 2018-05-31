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

string url_decode(string url);

string url_encode(string url);

string html_decode(string text);

string html_encode(string text);

string cli_encode(string text);

string read_line(FILE *file);


#endif
