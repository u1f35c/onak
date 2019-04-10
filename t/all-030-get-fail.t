#!/bin/sh
# Check retrieving a non existent keyid fails

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
if ! ${BUILDDIR}/onak -c $1 get 0x12345678 2>&1 | \
	grep -q 'Key not found'; then
	echo "* Did not correctly error on non-existent key"
	exit 1
fi

exit 0
