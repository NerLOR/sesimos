//
// Created by lorenz on 7/10/18.
//

#include <sys/stat.h>
#include <sys/time.h>
#include "Http.h"

unsigned long getMicros() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (unsigned long) (1000000 * tv.tv_sec + tv.tv_usec);
}

string getHttpDate() {
    time_t rawtime;
    time(&rawtime);
    return getHttpDate(rawtime);
}

string getHttpDate(string filename) {
    struct stat attrib;
    stat(filename.c_str(), &attrib);
    return getHttpDate(attrib.st_ctime);
}

string getHttpDate(time_t time) {
    char buffer[64];
    struct tm *timeinfo = gmtime(&time);
    strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", timeinfo);
    return string(buffer);
}
