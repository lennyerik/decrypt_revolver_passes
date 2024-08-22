#!/bin/bash
set -xe

clang -shared -fPIC -o preload.so preload.c
clang -o decrypt_pass decrypt_pass.c
LD_PRELOAD="./preload.so" ./decrypt_pass
