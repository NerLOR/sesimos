.DEFAULT_GOAL := install

packages:
	@echo "Installing packages..."
	sudo apt-get install gcc libmagic-dev libssl-dev php-fpm
	@echo "Finished downloading!"

compile:
	@mkdir -p bin
	gcc src/necronda-server.c -o bin/necronda-server -std=c11 -lssl -lcrypto -lmagic -lz -lmaxminddb -Wall

compile-debian:
	@mkdir -p bin
	gcc src/necronda-server.c -o bin/necronda-server -std=c11 -lssl -lcrypto -lmagic -lz -lmaxminddb -Wall \
		-D MAGIC_FILE="\"/usr/share/file/magic.mgc\"" \
		-D PHP_FPM_SOCKET="\"/var/run/php/php7.3-fpm.sock\""

install: | packages compile
	@echo "Finished!"
