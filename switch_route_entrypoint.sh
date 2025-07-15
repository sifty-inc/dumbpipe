#!/bin/bash
set -x

read -r SUBNET DEV SRC <<<$(ip route | awk '/192\.168\./ {print $1, $3, $9}' | head -n1)
GW="${SUBNET%0/24}1"
ip route del default 2>/dev/null
ip route add default via "$GW" dev "$DEV"

exec "$@"
