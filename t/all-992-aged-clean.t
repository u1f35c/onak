#!/bin/sh
# Check that 'onak clean-aged' removes the matched keys from the backend.

set -e

if [ "$2" = "fs" ] || [ "$2" = "hkp" ] || [ "$2" = "keyring" ]; then
	exit 0
fi

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
${BUILDDIR}/onak -c $1 clean-aged 1y
if ! ${BUILDDIR}/onak -c $1 get 0x94FA372B2DA8B985 2>&1 | \
	grep -q 'Key not found'; then
	echo "* 'onak clean-aged' did not remove the matched key"
	exit 1
fi

exit 0
