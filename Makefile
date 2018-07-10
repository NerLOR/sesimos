.DEFAULT_GOAL := install

packages:
	@echo "Installing packages..."
	sudo apt-get install g++ libmagic-dev libssl-dev php-cgi
	@echo "Finished downloading!"

update:
	@echo "Updating imported git repos..."
	cd CppNet
	git pull
	cd ..
	@echo "Finished updating!"

compile:
	@echo "Compiling..."
	@mkdir -p bin
	g++ src/necronda-server.cpp -o bin/necronda-server -std=c++17 -fPIC -pthread -lz -lmagic -lssl -ldl -lcrypto
	@echo "Finished compiling!"

install: | packages update compile
	@echo "Finished!"
