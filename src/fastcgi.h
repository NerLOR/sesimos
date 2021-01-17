/**
 * Necronda Web Server
 * FastCGI interface implementation (header file)
 * src/fastcgi.h
 * Lorenz Stechauner, 2020-12-26
 */

#ifndef NECRONDA_SERVER_FASTCGI_H
#define NECRONDA_SERVER_FASTCGI_H

#define FASTCGI_CHUNKED 1
#define FASTCGI_COMPRESS 2

#include "necronda-server.h"
#include "http.h"
#include "uri.h"
#include "client.h"

#include <sys/un.h>
#include <zlib.h>


typedef struct {
    int socket;
    unsigned short req_id;
    char *out_buf;
    unsigned short out_len;
    unsigned short out_off;
} fastcgi_conn;

char *fastcgi_add_param(char *buf, const char *key, const char *value);

int fastcgi_init(fastcgi_conn *conn, unsigned int client_num, unsigned int req_num, const sock *client,
                 const http_req *req, const http_uri *uri);

int fastcgi_close_stdin(fastcgi_conn *conn);

int fastcgi_php_error(const char *msg, int msg_len, char *err_msg);

int fastcgi_header(fastcgi_conn *conn, http_res *res, char *err_msg);

int fastcgi_send(fastcgi_conn *conn, sock *client, int flags);

int fastcgi_receive(fastcgi_conn *conn, sock *client, unsigned long len);


/*
 * Listening socket file number
 */
#define FCGI_LISTENSOCK_FILENO 0

typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} FCGI_Header;

/*
 * Number of bytes in a FCGI_Header.  Future versions of the protocol
 * will not reduce this number.
 */
#define FCGI_HEADER_LEN  8

/*
 * Value for version component of FCGI_Header
 */
#define FCGI_VERSION_1           1

/*
 * Values for type component of FCGI_Header
 */
#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE (FCGI_UNKNOWN_TYPE)

/*
 * Value for requestId component of FCGI_Header
 */
#define FCGI_NULL_REQUEST_ID     0

typedef struct {
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} FCGI_BeginRequestBody;

typedef struct {
    FCGI_Header header;
    FCGI_BeginRequestBody body;
} FCGI_BeginRequestRecord;

/*
 * Mask for flags component of FCGI_BeginRequestBody
 */
#define FCGI_KEEP_CONN  1

/*
 * Values for role component of FCGI_BeginRequestBody
 */
#define FCGI_RESPONDER  1
#define FCGI_AUTHORIZER 2
#define FCGI_FILTER     3

typedef struct {
    unsigned char appStatusB3;
    unsigned char appStatusB2;
    unsigned char appStatusB1;
    unsigned char appStatusB0;
    unsigned char protocolStatus;
    unsigned char reserved[3];
} FCGI_EndRequestBody;

typedef struct {
    FCGI_Header header;
    FCGI_EndRequestBody body;
} FCGI_EndRequestRecord;

/*
 * Values for protocolStatus component of FCGI_EndRequestBody
 */
#define FCGI_REQUEST_COMPLETE 0
#define FCGI_CANT_MPX_CONN    1
#define FCGI_OVERLOADED       2
#define FCGI_UNKNOWN_ROLE     3

/*
 * Variable names for FCGI_GET_VALUES / FCGI_GET_VALUES_RESULT records
 */
#define FCGI_MAX_CONNS  "FCGI_MAX_CONNS"
#define FCGI_MAX_REQS   "FCGI_MAX_REQS"
#define FCGI_MPXS_CONNS "FCGI_MPXS_CONNS"

typedef struct {
    unsigned char type;
    unsigned char reserved[7];
} FCGI_UnknownTypeBody;

typedef struct {
    FCGI_Header header;
    FCGI_UnknownTypeBody body;
} FCGI_UnknownTypeRecord;

#endif //NECRONDA_SERVER_FASTCGI_H
