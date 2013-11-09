#!/bin/sh
# Check we can retrieve a key by keyid

set -e

cd t
../onak -b -c test.conf add < ../keys/noodles.key
if ! ../onak -c test.conf get 0x2DA8B985 2> /dev/null | \
	grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----'; then
	echo "* Did not correctly retrieve key by keyid."
	exit 1
fi

exit 0
