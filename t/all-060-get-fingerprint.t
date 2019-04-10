#!/bin/sh
# Check we can retrieve a key by key fingerprint

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
if ! ${BUILDDIR}/onak -c $1 get 0x0E3A94C3E83002DAB88CCA1694FA372B2DA8B985 2> /dev/null | \
	grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----'; then
	echo "* Did not correctly retrieve key by keyid."
	exit 1
fi

exit 0
