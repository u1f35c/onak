#!/bin/sh
# Check we can delete a key successfully with the fs backend.

set -e

cd t
../onak -b -c $1 add < ../keys/noodles.key
../onak -b -c $1 delete 0x2DA8B985
if [ -e db/key/2D/A8/2DA8B985/94FA372B2DA8B985 ]; then
	echo "* Did not correctly delete key using fs backend"
	exit 1
fi

exit 0
