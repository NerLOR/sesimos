
CC=gcc
CFLAGS=-std=gnu11 -Wall
LIBS=-lssl -lcrypto -lmagic -lz -lmaxminddb -lbrotlienc

DEBIAN_OPTS=-D CACHE_MAGIC_FILE="\"/usr/share/file/magic.mgc\"" -D PHP_FPM_SOCKET="\"/var/run/php/php7.4-fpm.sock\""

packages:
	@echo "Installing packages..."
	sudo apt install gcc php-fpm libmagic-dev libssl-dev libmaxminddb-dev
	@echo "Finished downloading!"

permit:
	sudo setcap 'cap_net_bind_service=+ep' "$(shell pwd)/bin/necronda-server"

compile:
	@mkdir -p bin
	$(CC) src/lib/*.c -o bin/libnecrondaserver.so --shared -fPIC $(CFLAGS) $(LIBS)
	$(CC) src/necronda-server.c -o bin/necronda-server $(CFLAGS) $(LIBS) \
		-Lbin -lnecrondaserver -Wl,-rpath=$(shell pwd)/bin

compile-prod:
	@mkdir -p bin
	$(CC) src/lib/*.c -o bin/libnecrondaserver.so --shared -fPIC $(CFLAGS) $(LIBS) $(DEBIAN_OPTS) -O3
	$(CC) src/necronda-server.c -o bin/necronda-server $(CFLAGS) $(LIBS) $(DEBIAN_OPTS) -O3 \
		-Lbin -lnecrondaserver -Wl,-rpath=$(shell pwd)/bin
