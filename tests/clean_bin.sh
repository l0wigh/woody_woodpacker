#!/bin/bash

gcc -m32 hello.c -o hello32
gcc hello.c -o hello64
cp hello64 hello_blocked
chmod 000 hello_blocked