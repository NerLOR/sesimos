install:
	@echo "Start compiling..."
	g++ src/necronda-server.cpp -o bin/necronda-server -std=c++17 -fPIC
	@echo "Finished compiling!"
