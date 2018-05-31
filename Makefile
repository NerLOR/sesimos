packages:
	@echo "Installing packages..."
	sudo apt-get install g++
	@echo "Finished downloading!"

compile:
	@echo "Compiling..."
	g++ src/necronda-server.cpp -o bin/necronda-server -std=c++17 -fPIC -pthread -lz -lmagic -lssl -ldl -lcrypto
	@echo "Finished compiling!"

install: | packages compile
	@echo "Finished!"
