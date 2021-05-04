/**
 * Necronda Web Server
 * MaxMind GeoIP Database interface (header file)
 * src/lib/geoip.h
 * Lorenz Stechauner, 2021-05-04
 */


#ifndef NECRONDA_SERVER_GEOIP_H
#define NECRONDA_SERVER_GEOIP_H

#include <maxminddb.h>

#define GEOIP_MAX_SIZE 8192

MMDB_entry_data_list_s *mmdb_json(MMDB_entry_data_list_s *list, char *str, long *str_off, long str_len);

#endif //NECRONDA_SERVER_GEOIP_H
