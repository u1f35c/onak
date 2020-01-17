#!/bin/sh
# Check we can retrieve a key by keyid

set -e

# Backends should really support full fingerprint retrieval, but they don't
# always.
if [ "$2" = "file" ]; then
	exit 0
fi

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
if ! ${BUILDDIR}/onak -c $1 index 0x448B17C122A22C19FE289DC1045281F1B9A66E35 2> /dev/null | \
	grep -q -- 'noodles@earth.li'; then
	echo "* Did not correctly retrieve key by subkey fingerprint."
	exit 1
fi
if ${BUILDDIR}/onak -e -c $1 index 0x448B17C122A22C19FE289DC1045281F1B9A66E35 2> /dev/null | \
	grep -q -- 'noodles@earth.li'; then
	echo "* Incorrectly retrieved key by subkey fingerprint."
	exit 1
fi

exit 0
