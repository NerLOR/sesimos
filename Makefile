
CFLAGS=-std=c11 -Wall
INCLUDE=-lssl -lcrypto -lmagic -lz -lmaxminddb
LIBS=src/lib/*.c

DEBIAN_OPTS=-D MAGIC_FILE="\"/usr/share/file/magic.mgc\"" -D PHP_FPM_SOCKET="\"/var/run/php/php7.3-fpm.sock\""

packages:
	@echo "Installing packages..."
	sudo apt install gcc php-fpm libmagic-dev libssl-dev libmaxminddb-dev
	@echo "Finished downloading!"

permit:
	sudo setcap 'cap_net_bind_service=+ep' "$(shell pwd)/bin/necronda-server"

compile:
	@mkdir -p bin
	gcc $(LIBS) -o bin/libnecronda-server.so --shared -fPIC $(CFLAGS) $(INCLUDE)
	gcc src/necronda-server.c -o bin/necronda-server $(CFLAGS) $(INCLUDE) \
		-Lbin -lnecronda-server -Wl,-rpath=$(shell pwd)/bin

compile-debian:
	@mkdir -p bin
	gcc $(LIBS) -o bin/libnecronda-server.so --shared -fPIC $(CFLAGS) $(INCLUDE) \
		$(DEBIAN_OPTS)
	gcc src/necronda-server.c -o bin/necronda-server $(CFLAGS) $(INCLUDE) \
		-Lbin -lnecronda-server -Wl,-rpath=$(shell pwd)/bin \
		$(DEBIAN_OPTS)
