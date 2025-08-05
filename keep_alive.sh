#!/bin/bash
cd "$(dirname "${BASH_SOURCE[0]}")"

while [ 1 = 1 ]; do
	echo
	echo
	echo '***** run dumbpipe'
	./dumbpipe socks-server-forward --auto-shutdown 86400
	sleep 1
done
exit 0
