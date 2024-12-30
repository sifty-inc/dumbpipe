#!/bin/bash

./socks5 &

./dumbpipe listen-tcp --host 0.0.0.0:1080
