#!/bin/sh
# Check we can add a key successfully with the db4 backend.

set -e

cd t
../onak -b -c $1 add < ../keys/noodles.key
if [ ! -e db/worddb -o ! -e db/id32db -o ! -e db/keydb.0.db ]; then
	echo Did not correctly add key using db4 backend.
	exit 1
fi

exit 0
