#!/bin/sh
# Check we can index a key by some uid text

set -e

# Backends should really support this, but the file one is as simple as
# possible, so doesn't. Skip the test for it.
if [ "$2" = "file" ]; then
	exit 0
fi

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/v6-test.key
if ! ${BUILDDIR}/onak -c $1 index noodles 2> /dev/null | \
	grep -q -- \
	'pub    255e/0xB06F64299C663128 2025/07/14 Test v6 key <noodles@test>'; then
	echo "* Did not correctly retrieve key by text"
	exit 1
fi

exit 0
