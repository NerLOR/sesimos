.DEFAULT_GOAL := install

packages:
	@echo "Installing packages..."
	sudo apt-get install gcc libmagic-dev libssl-dev php-cgi
	@echo "Finished downloading!"

compile:
	@mkdir -p bin
	gcc src/necronda-server.c -o bin/necronda-server -std=c11 -lssl -lcrypto -lmagic

install: | packages update compile
	@echo "Finished!"
