#!/bin/sh
# Check we can retrieve a key by keyid

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/v5-test.key
if ! ${BUILDDIR}/onak -c $1 get 0x19347BC987246402 2> /dev/null | \
	grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----'; then
	echo "* Did not correctly retrieve key by keyid."
	exit 1
fi

exit 0
