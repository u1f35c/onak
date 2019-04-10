#!/bin/sh
# Check we can index a key by SKS hash

set -e

# Backends should really support this, but the file one is as simple as
# possible, so doesn't. Skip the test for it.
if [ "$2" = "file" ]; then
	exit 0
fi

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
if ! ${BUILDDIR}/onak -c $1 hget 81929DAE08B8F80888DA524923B93067 2> /dev/null | \
	grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----'; then
	echo "* Did not correctly retrieve key by text"
	exit 1
fi

exit 0
