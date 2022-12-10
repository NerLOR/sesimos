
#include <openssl/crypto.h>


int SSL_write(SSL *ssl, const void *buf, int num) {
    return num;
}

int SSL_read(SSL *ssl, void *buf, int num) {
    return num;
}

int SSL_peek(SSL *ssl, void *buf, int num) {
    return num;
}

int SSL_get_error(const SSL *s, int ret_code) {
    return 0;
}

const char *ERR_reason_error_string(unsigned long e) {
    return "";
}

int SSL_shutdown(SSL *s) {
    return 0;
}

void SSL_free(SSL *ssl) {}

unsigned long ERR_get_error(void) {
    return 0;
}
