
CC=gcc
CFLAGS=-std=gnu11 -Wno-unused-but-set-variable -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_SVID_SOURCE -D_POSIX_C_SOURCE=200809L
LDFLAGS=-lssl -lcrypto -lmagic -lz -lmaxminddb -lbrotlienc

DEBIAN_OPTS=-D CACHE_MAGIC_FILE="\"/usr/share/file/magic.mgc\"" -D PHP_FPM_SOCKET="\"/var/run/php/php8.2-fpm.sock\""

.PHONY: all prod debug default debian permit clean test
all: prod
default: bin bin/lib bin/sesimos

prod: CFLAGS += -O3
prod: default

debug: CFLAGS += -Wall -pedantic
debug: default

debian: CFLAGS += $(DEBIAN_OPTS)
debian: prod

test: CFLAGS += -include test/mock_*.h
test: bin bin/test
	bin/test


bin:
	mkdir -p bin

bin/lib:
	mkdir -p bin/lib


bin/test: test/mock_*.c test/test_*.c src/lib/utils.c src/lib/sock.c
	$(CC) -o $@ $(CFLAGS) $^ -lcriterion


bin/%.o: src/%.c
	$(CC) -c -o $@ $(CFLAGS) $<

bin/lib/%.o: src/lib/%.c
	$(CC) -c -o $@ $(CFLAGS) $<

bin/sesimos: bin/server.o bin/client.o \
			 bin/lib/cache.o bin/lib/compress.o bin/lib/config.o bin/lib/fastcgi.o bin/lib/geoip.o \
			 bin/lib/http.o bin/lib/http_static.o bin/lib/rev_proxy.o bin/lib/sock.o bin/lib/uri.o \
		     bin/lib/utils.o bin/lib/websocket.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)


bin/server.o: src/server.h src/defs.h src/client.h src/lib/cache.h src/lib/config.h src/lib/sock.h \
              src/lib/rev_proxy.h src/lib/geoip.h src/lib/utils.h

bin/client.o: src/client.h src/defs.h src/server.h src/lib/utils.h src/lib/config.h src/lib/sock.h \
              src/lib/http.h src/lib/rev_proxy.h src/lib/fastcgi.h src/lib/cache.h src/lib/geoip.h src/lib/compress.h \
              src/lib/websocket.h

bin/lib/cache.o: src/lib/cache.h src/lib/utils.h src/lib/uri.h src/lib/compress.h

bin/lib/compress.o: src/lib/compress.h

bin/lib/config.o: src/lib/config.h src/lib/utils.h src/lib/uri.h

bin/lib/fastcgi.o: src/lib/fastcgi.h src/server.h src/lib/utils.h src/lib/compress.h src/lib/http.h \
                   src/lib/uri.h src/lib/include/fastcgi.h

bin/lib/geoip.o: src/lib/geoip.h

bin/lib/http.o: src/lib/http.h src/lib/utils.h src/lib/compress.h src/lib/sock.h

bin/lib/rev_proxy.o: src/lib/rev_proxy.h src/defs.h src/server.h src/lib/compress.h

bin/lib/sock.o: src/lib/sock.h

bin/lib/uri.o: src/lib/uri.h src/lib/utils.h

bin/lib/utils.o: src/lib/utils.h

bin/lib/websocket.o: src/lib/websocket.h src/defs.h src/lib/utils.h src/lib/sock.h


permit:
	sudo setcap 'cap_net_bind_service=+ep' "$(shell pwd)/bin/sesimos"

clean:
	rm -rf bin/*
