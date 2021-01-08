/**
 * Necronda Web Server
 * Main executable (header file)
 * src/necronda-server.c
 * Lorenz Stechauner, 2020-12-03
 */

#ifndef NECRONDA_SERVER_NECRONDA_SERVER_H
#define NECRONDA_SERVER_NECRONDA_SERVER_H

#include <stdio.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <wait.h>
#include <sys/types.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/dh.h>
#include <maxminddb.h>
#include <dirent.h>


#define NUM_SOCKETS 2
#define MAX_CHILDREN 1024
#define MAX_MMDB 3
#define MAX_HOST_CONFIG 64
#define LISTEN_BACKLOG 16
#define REQ_PER_CONNECTION 100
#define CLIENT_TIMEOUT 3600
#define SERVER_TIMEOUT 4

#define CHUNK_SIZE 8192
#define CLIENT_MAX_HEADER_SIZE 8192
#define FILE_CACHE_SIZE 1024
#define GEOIP_MAX_SIZE 8192

#define SHM_KEY_CACHE 255641
#define SHM_KEY_CONFIG 255642

#define ERR_STR "\x1B[1;31m"
#define CLR_STR "\x1B[0m"
#define BLD_STR "\x1B[1m"
#define WRN_STR "\x1B[1;33m"
#define BLUE_STR "\x1B[34m"
#define HTTP_STR "\x1B[1;31m"
#define HTTPS_STR "\x1B[1;32m"

#define HTTP_1XX_STR "\x1B[1;32m"
#define HTTP_2XX_STR "\x1B[1;32m"
#define HTTP_3XX_STR "\x1B[1;33m"
#define HTTP_4XX_STR "\x1B[1;31m"
#define HTTP_5XX_STR "\x1B[1;31m"

#define NECRONDA_VERSION "4.1"
#define SERVER_STR "Necronda/" NECRONDA_VERSION
#define NECRONDA_ZLIB_LEVEL 9

#ifndef DEFAULT_HOST
#define DEFAULT_HOST "www.necronda.net"
#endif
#ifndef MAGIC_FILE
#define MAGIC_FILE "/usr/share/file/misc/magic.mgc"
#endif
#ifndef PHP_FPM_SOCKET
#define PHP_FPM_SOCKET "/var/run/php-fpm/php-fpm.sock"
#endif
#ifndef DEFAULT_CONFIG_FILE
#define DEFAULT_CONFIG_FILE "/etc/necronda-server/necronda-server.conf"
#endif

int sockets[NUM_SOCKETS];
pid_t children[MAX_CHILDREN];
MMDB_s mmdbs[MAX_MMDB];

char *client_addr_str, *client_addr_str_ptr, *server_addr_str, *server_addr_str_ptr, *client_host_str;

#endif //NECRONDA_SERVER_NECRONDA_SERVER_H
