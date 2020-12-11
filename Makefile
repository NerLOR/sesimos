.DEFAULT_GOAL := install

packages:
	@echo "Installing packages..."
	sudo apt-get install gcc libmagic-dev libssl-dev php-cgi
	@echo "Finished downloading!"

compile:
	@echo "Compiling..."
	@mkdir -p bin
	gcc src/necronda-server.c -o bin/necronda-server -std=c11 -D_POSIX_C_SOURCE -lssl -lcrypto
	@echo "Finished compiling!"

install: | packages update compile
	@echo "Finished!"
