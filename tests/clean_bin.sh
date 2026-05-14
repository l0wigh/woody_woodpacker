#!/bin/bash

cd tests
gcc -m32 hello.c -o hello32
gcc hello.c -o hello64
gcc hello.c -no-pie -o hello64_nopie
cp hello64 hello_blocked
chmod 000 hello_blocked
