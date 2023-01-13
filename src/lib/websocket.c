/**
 * sesimos - secure, simple, modern web server
 * @brief WebSocket reverse proxy
 * @file src/lib/websocket.c
 * @author Lorenz Stechauner
 * @date 2022-08-16
 */

#include "../logger.h"
#include "websocket.h"
#include "utils.h"

#include <string.h>
#include <openssl/sha.h>

static const char ws_key_uuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

int ws_calc_accept_key(const char *key, char *accept_key) {
    if (key == NULL || accept_key == NULL)
        return -1;

    char input[256] = "";
    unsigned char output[SHA_DIGEST_LENGTH];
    strcat(input, key);
    strcat(input, ws_key_uuid);

    if (SHA1((unsigned char *) input, strlen(input), output) == NULL) {
        return -2;
    }

    base64_encode(output, sizeof(output), accept_key, NULL);

    return 0;
}

int ws_recv_frame_header(sock *s, ws_frame *frame) {
    unsigned char buf[12];

    if (sock_recv_x(s, buf, 2, 0) == -1) {
        error("Unable to receive from socket");
        return -1;
    }

    unsigned short bits = (buf[0] << 8) | buf[1];
    frame->f_fin = (bits >> 15) & 1;
    frame->f_rsv1 = (bits >> 14) & 1;
    frame->f_rsv2 = (bits >> 13) & 1;
    frame->f_rsv3 = (bits >> 12) & 1;
    frame->opcode = (bits >> 8) & 0xF;
    frame->f_mask = (bits >> 7) & 1;
    unsigned short len = (bits & 0x7F);

    int remaining = frame->f_mask ? 4 : 0;
    if (len == 126) {
        remaining += 2;
    } else if (len == 127) {
        remaining += 8;
    }

    if (sock_recv_x(s, buf, remaining, 0) == -1) {
        error("Unable to receive from socket");
        return -1;
    }

    if (len == 126) {
        frame->len = (((unsigned long) buf[0]) << 8) | ((unsigned long) buf[1]);
    } else if (len == 127) {
        frame->len =
                (((unsigned long) buf[0]) << 56) |
                (((unsigned long) buf[1]) << 48) |
                (((unsigned long) buf[2]) << 40) |
                (((unsigned long) buf[3]) << 32) |
                (((unsigned long) buf[4]) << 24) |
                (((unsigned long) buf[5]) << 16) |
                (((unsigned long) buf[6]) << 8) |
                (((unsigned long) buf[7]) << 0);
    } else {
        frame->len = len;
    }

    if (frame->f_mask) memcpy(frame->masking_key, buf + (remaining - 4), 4);

    return 0;
}

int ws_send_frame_header(sock *s, ws_frame *frame) {
    unsigned char buf[14], *ptr = buf;

    unsigned short len;
    if (frame->len > 0x7FFF) {
        len = 127;
    } else if (frame->len > 125) {
        len = 126;
    } else {
        len = frame->len;
    }

    unsigned short bits =
            (frame->f_fin << 15) |
            (frame->f_rsv1 << 14) |
            (frame->f_rsv2 << 13) |
            (frame->f_rsv3 << 12) |
            (frame->opcode << 8) |
            (frame->f_mask << 7) |
            len;

    ptr++[0] = bits >> 8;
    ptr++[0] = bits & 0xFF;

    if (len >= 126) {
        for (int i = (len == 126 ? 2 : 8) - 1; i >= 0; i--)
            ptr++[0] = (unsigned char) ((frame->len >> (i * 8)) & 0xFF);
    }

    if (frame->f_mask) {
        memcpy(ptr, frame->masking_key, 4);
        ptr += 4;
    }

    long ret = sock_send_x(s, buf, ptr - buf, frame->len != 0 ? MSG_MORE : 0);
    if (ret < 0) {
        error("Unable to send to socket");
        return -1;
    } else if (ret != ptr - buf) {
        error("Unable to send to socket");
        return -2;
    }

    return 0;
}
