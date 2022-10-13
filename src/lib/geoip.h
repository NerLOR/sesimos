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

#define GEOIP_MAX_SIZE 8192

MMDB_entry_data_list_s *mmdb_json(MMDB_entry_data_list_s *list, char *str, long *str_off, long str_len);

#endif //SESIMOS_GEOIP_H
