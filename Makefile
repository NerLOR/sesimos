
CC=gcc
CFLAGS=-std=gnu11 -Wno-unused-but-set-variable -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_SVID_SOURCE -D_POSIX_C_SOURCE=200809L
LDFLAGS=-lssl -lcrypto -lmagic -lz -lmaxminddb -lbrotlienc

DEBIAN_OPTS=-D CACHE_MAGIC_FILE="\"/usr/share/file/magic.mgc\"" -D PHP_FPM_SOCKET="\"/var/run/php/php7.4-fpm.sock\""

.PHONY: all prod debug default debian permit clean test
all: prod
default: bin bin/lib bin/worker bin/res bin/sesimos

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

bin/worker:
	mkdir -p bin/worker

bin/res:
	mkdir -p bin/res

bin/test: test/mock_*.c test/test_*.c src/lib/utils.c src/lib/sock.c src/lib/list.c
	$(CC) -o $@ $(CFLAGS) $^ -lcriterion


bin/%.o: src/%.c
	$(CC) -c -o $@ $(CFLAGS) $<

bin/lib/%.o: src/lib/%.c
	$(CC) -c -o $@ $(CFLAGS) $<

bin/worker/%.o: src/worker/%.c
	$(CC) -c -o $@ $(CFLAGS) $<

bin/res/%.o: bin/res/%.txt
	objcopy -I binary --rename-section .data=.rodata -O elf64-x86-64 $^ $@

bin/res/%.txt: res/%.*
	cp $^ $@
	echo -ne "\x00" >> $@

bin/sesimos: bin/server.o bin/logger.o bin/cache_handler.o bin/async.o bin/workers.o \
			 bin/worker/request_handler.o bin/worker/tcp_acceptor.o \
			 bin/worker/fastcgi_handler.o bin/worker/local_handler.o bin/worker/proxy_handler.o \
			 bin/lib/http_static.o bin/res/default.o bin/res/proxy.o bin/res/style.o \
			 bin/lib/compress.o bin/lib/config.o bin/lib/fastcgi.o bin/lib/geoip.o \
			 bin/lib/http.o  bin/lib/proxy.o bin/lib/sock.o bin/lib/uri.o \
		     bin/lib/utils.o bin/lib/websocket.o bin/lib/mpmc.o bin/lib/list.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)


bin/server.o: src/server.h src/defs.h src/cache_handler.h src/lib/config.h src/lib/sock.h \
              src/lib/proxy.h src/lib/geoip.h src/lib/utils.h src/logger.h

bin/logger.o: src/logger.h

bin/cache_handler.o: src/cache_handler.h src/lib/utils.h src/lib/uri.h src/lib/compress.h src/logger.h

bin/async.o: src/async.h src/logger.h

bin/workers.o: src/workers.h src/lib/mpmc.h src/worker/func.h

bin/worker/request_handler.o: src/worker/func.h

bin/worker/tcp_acceptor.o: src/worker/func.h

bin/worker/fastcgi_handler.o: src/worker/func.h

bin/worker/local_handler.o: src/worker/func.h

bin/worker/proxy_handler.o: src/worker/func.h

bin/lib/compress.o: src/lib/compress.h

bin/lib/config.o: src/lib/config.h src/lib/utils.h src/lib/uri.h src/logger.h

bin/lib/fastcgi.o: src/lib/fastcgi.h src/server.h src/lib/utils.h src/lib/compress.h src/lib/http.h \
                   src/lib/uri.h src/lib/include/fastcgi.h src/logger.h

bin/lib/geoip.o: src/lib/geoip.h

bin/lib/http.o: src/lib/http.h src/lib/utils.h src/lib/compress.h src/lib/sock.h src/logger.h

bin/lib/list.o: src/lib/list.h

bin/lib/mpmc.o: src/lib/mpmc.h src/logger.h

bin/lib/proxy.o: src/lib/proxy.h src/defs.h src/server.h src/lib/compress.h src/logger.h

bin/lib/sock.o: src/lib/sock.h

bin/lib/uri.o: src/lib/uri.h src/lib/utils.h

bin/lib/utils.o: src/lib/utils.h

bin/lib/websocket.o: src/lib/websocket.h src/defs.h src/lib/utils.h src/lib/sock.h src/logger.h


permit:
	sudo setcap 'cap_net_bind_service=+ep' "$(shell pwd)/bin/sesimos"

clean:
	rm -rf bin/*
