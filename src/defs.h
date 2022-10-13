/**
 * sesimos - secure, simple, modern web server
 * @brief Definitions
 * @file src/defs.h
 * @author Lorenz Stechauner
 * @date 2021-05-04
 */

#ifndef SESIMOS_DEF_H
#define SESIMOS_DEF_H

#define SERVER_VERSION "4.6"
#define SERVER_STR "Sesimos/" SERVER_VERSION
#define SERVER_STR_HTML "Sesimos&nbsp;web&nbsp;server&nbsp;" SERVER_VERSION

#define CHUNK_SIZE 8192

#ifndef DEFAULT_HOST
#   define DEFAULT_HOST "www.necronda.net"
#endif

#ifndef SERVER_NAME
#   define SERVER_NAME DEFAULT_HOST
#endif

#endif //SESIMOS_DEF_H
