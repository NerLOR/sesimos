install:
	@echo "Start compiling..."
	g++ src/necronda-server.cpp -o bin/necronda-server -std=c++17 -fPIC -pthread -lz -lmagic -lssl -ldl -lcrypto
	@echo "Finished compiling!"
