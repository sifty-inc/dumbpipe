#!/bin/bash

./socks5 &
trap "killall socks5" SIGTERM SIGINT

exec ./dumbpipe listen-tcp --host 0.0.0.0:1080
