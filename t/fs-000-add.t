#!/bin/sh
# Check we can add a key successfully with the fs backend.

set -e

cd t
../onak -b -c test.conf add < ../keys/noodles.key
if [ ! -e db/key/2D/A8/2DA8B985/94FA372B2DA8B985 ]; then
	echo Did not correctly add key using fs backend.
	exit 1
fi

exit 0
