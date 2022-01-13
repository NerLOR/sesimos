/**
 * Necronda Web Server
 * Definitions
 * src/necronda.h
 * Lorenz Stechauner, 2021-05-04
 */

#ifndef NECRONDA_SERVER_NECRONDA_H
#define NECRONDA_SERVER_NECRONDA_H

#define NECRONDA_VERSION "4.5"
#define SERVER_STR "Necronda/" NECRONDA_VERSION
#define SERVER_STR_HTML "Necronda&nbsp;web&nbsp;server&nbsp;" NECRONDA_VERSION

#ifndef DEFAULT_HOST
#   define DEFAULT_HOST "www.necronda.net"
#endif

#ifndef SERVER_NAME
#   define SERVER_NAME DEFAULT_HOST
#endif

#endif //NECRONDA_SERVER_NECRONDA_H
