#!/bin/sh
# Check we can retrieve a key by keyid

set -e

# Backends should really support this, but the file one is as simple as
# possible, so doesn't. Skip the test for it.
if [ "$2" = "file" ]; then
	exit 0
fi

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
if ! ${BUILDDIR}/onak -c $1 get 0xB9A66E35 2> /dev/null | \
	grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----'; then
	echo "* Did not correctly retrieve key by subkey id."
	exit 1
fi
if ! ${BUILDDIR}/onak -c $1 get 0xCF3FBAD1 2> /dev/null | \
	grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----'; then
	echo "* Did not correctly retrieve key by subkey id."
	exit 1
fi

exit 0
