
CC=gcc
CFLAGS=-std=gnu11 -Wall -Wno-unused-but-set-variable
LIBS=-lssl -lcrypto -lmagic -lz -lmaxminddb -lbrotlienc

DEBIAN_OPTS=-D CACHE_MAGIC_FILE="\"/usr/share/file/magic.mgc\"" -D PHP_FPM_SOCKET="\"/var/run/php/php7.4-fpm.sock\""

packages:
	@echo "Installing packages..."
	sudo apt install gcc php-fpm libmagic-dev libssl-dev libmaxminddb-dev
	@echo "Finished downloading!"

permit:
	sudo setcap 'cap_net_bind_service=+ep' "$(shell pwd)/bin/sesimos"

compile:
	@mkdir -p bin
	$(CC) src/lib/*.c -o bin/libsesimos.so --shared -fPIC $(CFLAGS) $(LIBS)
	$(CC) src/server.c src/client.c -o bin/sesimos $(CFLAGS) $(LIBS) \
		-Lbin -lsesimos -Wl,-rpath=$(shell pwd)/bin

compile-prod:
	@mkdir -p bin
	$(CC) src/lib/*.c -o bin/libsesimos.so --shared -fPIC $(CFLAGS) $(LIBS) $(DEBIAN_OPTS) -O3
	$(CC) src/server.c src/client.c -o bin/sesimos $(CFLAGS) $(LIBS) $(DEBIAN_OPTS) -O3 \
		-Lbin -lsesimos -Wl,-rpath=$(shell pwd)/bin
