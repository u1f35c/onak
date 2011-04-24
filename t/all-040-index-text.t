#!/bin/sh
# Check we can index a key by some uid text

set -e

# Backends should really support this, but the file one is as simple as
# possible, so doesn't. Skip the test for it.
if [ "$1" = "file" ]; then
	exit 0
fi

cd t
../onak -b -c test.conf add < ../keys/noodles.key
if ! ../onak -c test.conf index noodles 2> /dev/null | \
	grep -q -- 'pub   4096R/2DA8B985 2008/06/03 Jonathan McDowell'; then
	echo "* Did not correctly retrieve key by text"
	exit 1
fi

exit 0
