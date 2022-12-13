/**
 * sesimos - secure, simple, modern web server
 * @brief MaxMind GeoIP Database interface (header file)
 * @file src/lib/geoip.h
 * @author Lorenz Stechauner
 * @date 2021-05-04
 */


#ifndef SESIMOS_GEOIP_H
#define SESIMOS_GEOIP_H

#include <maxminddb.h>

#define GEOIP_MAX_JSON_SIZE 8192
#define GEOIP_MAX_MMDB 3

int geoip_init(const char *directory);

void geoip_free();

int geoip_lookup_country(struct sockaddr *addr, char *str);

#endif //SESIMOS_GEOIP_H
