.DEFAULT_GOAL := install

packages:
	@echo "Installing packages..."
	sudo apt-get install g++ libmagic-dev libssl-dev
	@echo "Finished downloading!"

compile:
	@echo "Compiling..."
	@mkdir bin
	g++ src/necronda-server.cpp -o bin/necronda-server -std=c++17 -fPIC -pthread -lz -lmagic -lssl -ldl -lcrypto
	@echo "Finished compiling!"

install: | packages compile
	@echo "Finished!"
