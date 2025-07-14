#!/bin/sh
# Check we can retrieve a key by key fingerprint

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/v6-test.key
if ! ${BUILDDIR}/onak -c $1 get 0xB06F64299C663128F97AD7C1D96EF5F535F824F2D749E96D621EB6EDC32A5E1D 2> /dev/null | \
	grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----'; then
	echo "* Did not correctly retrieve key by fingerprint."
	exit 1
fi

exit 0
