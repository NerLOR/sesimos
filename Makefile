.DEFAULT_GOAL := install

packages:
	@echo "Installing packages..."
	sudo apt-get install gcc libmagic-dev libssl-dev php-cgi
	@echo "Finished downloading!"

compile:
	@echo "Compiling..."
	@mkdir -p bin
	gcc src/necronda-server.c -o bin/necronda-server -std=c11 -fPIC -pthread -lz -lmagic -lssl -ldl -lcrypto
	@echo "Finished compiling!"

install: | packages update compile
	@echo "Finished!"
