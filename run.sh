#!/bin/bash
echo "-- Building and starting Necronda Server..."
make && \
 echo -e "-- Successfully finished compiling!\n" && \
 sleep 0.0625 && \
 echo -e "-- Starting Server...\n" && \
 authbind ./bin/necronda-server
