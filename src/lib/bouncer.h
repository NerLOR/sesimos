
#ifndef SESIMOS_BOUNCER_H
#define SESIMOS_BOUNCER_H

#include "http.h"
#include <netinet/in.h>

#define BOUNCER_SLOTS 60
#define BOUNCER_SECONDS_PER_SLOT 60

int bouncer_init(void);

void bouncer_destroy(void);

int bouncer_get_cid(const struct sockaddr_in6 *addr);

int bouncer_authorize(int cid);

void bouncer_record(int cid, const char *method, status_code_t status_code);

#endif //SESIMOS_BOUNCER_H
