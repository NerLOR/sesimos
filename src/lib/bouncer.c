
#include "utils.h"
#include "bouncer.h"

#include <errno.h>
#include <semaphore.h>
#include <string.h>


static const unsigned char IP4_BLOCKS[256] = {
     0 , 'P', 'E', 'N', 'n', 'E', 'D', 'D', 'n', 'n',  0 , 'D', 'n', 'n', 'P', 'n',
    'n', 'n', 'n', 'n', 'n', 'D', 'D', 'N', 'N', 'E', 'D', 'P', 'D', 'D', 'D', 'E',
    'N', 'D', 'n', 'n', 'P', 'E', 'n', 'P', 'N', 'A', 'P', 'p', 'n', 'n', 'E', 'n',
    'N', 'P', 'N', 'e', 'N', 'e', 'N', 'D', 'N', 'E', 'P', 'P', 'P', 'P', 'E', 'N',
    'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'n', 'N', 'N', 'N', 'E', 'E', 'E',
    'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E', 'N', 'E', 'E',
    'N', 'N', 'N', 'N', 'N', 'P', 'A', 'P', 'N', 'A', 'P', 'N', 'N', 'E', 'P', 'P',
    'P', 'P', 'P', 'P', 'P', 'P', 'P', 'P', 'P', 'P', 'P', 'P', 'P', 'P', 'P',  0 ,
    'n', 'n', 'n', 'n', 'n', 'P', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'e', 'n', 'n',
    'n', 'e', 'n', 'n', 'n', 'n', 'p', 'e', 'n', 'p', 'a', 'n', 'n', 'n', 'n', 'n',
    'n', 'n', 'n', 'p', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'p', 'n', 'N', 'N', 'P',
    'E', 'L', 'e', 'L', 'P', 'L', 'P', 'P', 'N', 'e', 'L', 'L', 'e', 'L', 'L', 'l',
    'n', 'E', 'E', 'E', 'a', 'A', 'n', 'N', 'L', 'L', 'p', 'P', 'N', 'N', 'N', 'N',
    'N', 'N', 'P', 'P', 'E', 'E', 'D', 'D', 'N', 'E', 'P', 'P', 'P', 'P', 'P', 'P',
    // ... reserved ...
};

int bouncer_get_cid(const struct sockaddr_in6 *addr) {
    // 20 bit
    const unsigned int a1 = ntohl(addr->sin6_addr.s6_addr32[0]);
    const unsigned int a2 = ntohl(addr->sin6_addr.s6_addr32[1]);
    const unsigned int a3 = ntohl(addr->sin6_addr.s6_addr32[2]);
    const unsigned int a4 = ntohl(addr->sin6_addr.s6_addr32[3]);
    if (a1 == 0 && a2 == 0 && a3 == 0x0000ffff) {
        // IPv4
        const unsigned char block = IP4_BLOCKS[a4 >> 24];
        if (block == 0 || (a4 & 0xfff00000) == 0xac100000 || (a4 & 0xffff0000) == 0xc0a80000)
            return -1;
        // compress first octet to 4 bit, and truncate last 4 bits
        return
            (((a4 >> 8) & 0x000f0000) ^ ((a4 >> 12) & 0x000f0000)) |
             ((a4 >> 8) & 0x0000ff00) |
             ((a4 >> 8) & 0x000000f0) |
            (((a4 >> 8) & 0x0000000f) ^ ((a4 >> 4) & 0x0000000f));
    } else {
        // IPv6
        if ((a1 & 0xffc00000) == 0xfe800000 || (a1 & 0xfe000000) == 0xfc000000)
            return -1;
        const unsigned int n1 = (a1 >> 16) ^ (a1 & 0xffff);
        const unsigned int n2 = (a2 >> 24) ^ ((a2 >> 16) & 0xff) ^ ((a2 >> 8) & 0xff) ^ (a2 & 0xff);
        return (((n1 << 8) & 0xfff00) ^ ((n1 << 4) & 0xf0000)) | n2;
    }
}

static long start = 0;
volatile static long last = 0;
volatile static unsigned char visits[BOUNCER_SLOTS][1048576][4];
static sem_t sem;

static int bouncer_slot(void);

int bouncer_init(void) {
    if (sem_init(&sem, 0, 1) != 0) {
        return -1;
    }
    start = time(NULL) / BOUNCER_SECONDS_PER_SLOT;
    return 0;
}

void bouncer_destroy(void) {
    sem_destroy(&sem);
}

static int bouncer_slot(void) {
    const long slot = time(NULL) / BOUNCER_SECONDS_PER_SLOT;

    while (sem_wait(&sem) != 0) {
        if (errno != EINTR) return -1;
        errno = 0;
    }
    if (slot - last > BOUNCER_SLOTS) {
        memset((void *)visits, 0, sizeof(visits));
    } else  {
        for (long i = last + 1; i <= slot; i++) {
            memset((void *)visits[i % BOUNCER_SLOTS], 0, sizeof(visits[0]));
        }
    }
    sem_post(&sem);

    last = slot;
    return slot % BOUNCER_SLOTS;
}

int bouncer_authorize(const int cid) {
    const int slot = bouncer_slot();
    if (cid < 0) return 1;
    const int net = cid & 0xfff00;
    int net_success_1h = 0, net_redirect_1h = 0, net_fail_1h = 0, net_other_1h = 0;
    int success_1h = 0, redirect_1h = 0, fail_1h = 0, other_1h = 0;
    int success_5m = 0, redirect_5m = 0, fail_5m = 0, other_5m = 0;
    for (int i = 0; i < BOUNCER_SLOTS; i++) {
        const int s = (slot - i + BOUNCER_SLOTS) % BOUNCER_SLOTS;
        success_1h += visits[s][cid][0];
        redirect_1h += visits[s][cid][1];
        fail_1h += visits[s][cid][2];
        other_1h += visits[s][cid][3];
        for (int j = 0; j < 256; j++) {
            net_success_1h += visits[s][net | j][0];
            net_redirect_1h += visits[s][net | j][1];
            net_fail_1h += visits[s][net | j][2];
            net_other_1h += visits[s][net | j][3];
        }
        if (i <= 5) {
            success_5m += visits[s][cid][0];
            redirect_5m += visits[s][cid][1];
            fail_5m += visits[s][cid][2];
            other_5m += visits[s][cid][3];
        }
    }
    const long diff = slot - start;
    const int mult = diff < 15 ? 4 : diff < 25 ? 3 : diff < 35 ? 2 : 1;
    const int net_total_1h = (net_success_1h + net_redirect_1h + net_fail_1h + net_other_1h) * mult;
    const int total_1h = (success_1h + redirect_1h + fail_1h + other_1h) * mult;
    if (net_total_1h > 2000 || total_1h > 1000) {
        return 3600;
    } else if (fail_5m > 10 && fail_5m > success_5m * 2) {
        return 300;
    } else {
        return 0;
    }
}

void bouncer_record(const int cid, const char *method, const status_code_t status_code) {
    const int slot = bouncer_slot();
    if (cid < 0) return;
    const int m = status_code / 100;
    const int i = m == 2 || status_code == 304 ? 0 : m == 3 ? 1 : m == 4 ? 2 : 3;

    if (m == 0 && !streq(method, "GET") && !streq(method, "HEAD"))
        return;

    while (sem_wait(&sem) != 0) {
        if (errno != EINTR) return;
        errno = 0;
    }
    if (visits[slot][cid][i] != 255) visits[slot][cid][i]++;
    sem_post(&sem);
}
