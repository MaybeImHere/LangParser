#!/usr/bin/bash

clang -Wall -Wpedantic -Wno-newline-eof -g -O0 stack.c err.c main.c -o compiled/main