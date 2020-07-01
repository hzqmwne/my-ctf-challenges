#!/bin/sh

cd /home/pwn
exec ./simple_echoserver 2>/dev/null
exit

