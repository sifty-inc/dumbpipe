#!/bin/bash
set -x

ip link set eth0 mtu 1428
ip link set eth1 mtu 1428
iptables -t mangle -A OUTPUT -p tcp --syn -j TCPMSS --set-mss 1380

printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions timeout:2 attempts:2 rotate use-vc ndots:1\n' > /etc/resolv.conf


exec "$@"
