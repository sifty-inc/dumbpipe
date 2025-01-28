#!/bin/bash

./socks5 &
trap "killall socks5" SIGTERM SIGINT

exec ./dumbpipe listen-tcp --host 127.0.0.1:1080
