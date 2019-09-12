#!/usr/bin/env bash

mkdir -p build
cd build
cmake -DENABLE_SYS_LIBGO=ON -DLibgo_DIR=/usr/local/libgo -DENABLE_TUTORIAL=ON ..