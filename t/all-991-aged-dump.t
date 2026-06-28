#!/bin/sh
# Check that 'onak dump-aged' emits an ASCII-armored OpenPGP block when
# a matching key is present.

set -e

if [ "$2" = "fs" ] || [ "$2" = "hkp" ] || [ "$2" = "keyring" ]; then
	exit 0
fi

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
if ! ${BUILDDIR}/onak -c $1 dump-aged 1y 2>/dev/null | \
	grep -q -- '^-----BEGIN PGP PUBLIC KEY BLOCK-----'; then
	echo "* 'onak dump-aged 1y' did not emit an armored key block"
	exit 1
fi

exit 0
