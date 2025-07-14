#!/bin/sh
# Check we can retrieve a key by subkeyid

set -e

# Backends should really support this, but the file one is as simple as
# possible, so doesn't. Skip the test for it.
if [ "$2" = "file" ]; then
	exit 0
fi

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/v6-test.key
if ! ${BUILDDIR}/onak -c $1 get 0x7B920EF92EB78162 2> /dev/null | \
	grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----'; then
	echo "* Did not correctly retrieve key by subkey id."
	exit 1
fi

exit 0
