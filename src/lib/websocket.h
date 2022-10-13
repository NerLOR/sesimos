/**
 * sesimos - secure, simple, modern web server
 * @brief WebSocket reverse proxy (header file)
 * @file src/lib/websocket.h
 * @author Lorenz Stechauner
 * @date 2022-08-16
 */

#ifndef SESIMOS_WEBSOCKET_H
#define SESIMOS_WEBSOCKET_H

#include "sock.h"

#define WS_TIMEOUT 3600

const char *ws_key_uuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

typedef struct {
    unsigned char f_fin:1;
    unsigned char f_rsv1:1;
    unsigned char f_rsv2:1;
    unsigned char f_rsv3:1;
    unsigned char opcode:4;
    unsigned char f_mask:1;
    unsigned long len;
    char masking_key[4];
} ws_frame;

int ws_calc_accept_key(const char *key, char *accept_key);

int ws_recv_frame_header(sock *s, ws_frame *frame);

int ws_send_frame_header(sock *s, ws_frame *frame);

int ws_handle_connection(sock *s1, sock *s2);

#endif //SESIMOS_WEBSOCKET_H
