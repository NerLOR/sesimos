#!/bin/bash
echo "-- Building and starting Necronda Server..."
make compile && \
 echo "-- Successfully finished compiling!" && \
 echo "-- Starting Server..." && \
 ./bin/necronda-server
