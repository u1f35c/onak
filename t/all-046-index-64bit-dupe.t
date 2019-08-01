#!/bin/sh
# Check we can index a key by some uid text

set -e

# Backends should really support storing keys with full fingerprints,
# but the file + fs backends only do 64 bit keys IDs for simplicity.
# Skip the test for them.
if [ "$2" = "file" -o "$2" = "fs" ]; then
	exit 0
fi

cd ${WORKDIR}
# Import 2 keys with the same 64 bit key ID
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/DDA252EBB8EBE1AF-1.key
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/DDA252EBB8EBE1AF-2.key
# Add an extra key so we know we're not just returning all of them
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
c=$(${BUILDDIR}/onak -c $1 index 0xDDA252EBB8EBE1AF 2> /dev/null | \
		grep -c -- '^pub   ')
if [ $c != 2 ]; then
	echo "* Did not correctly retrieve keys with duplicate 64-bit keyids"
	exit 1
fi

exit 0
