#!/bin/sh
# Check deleting a key results in no longer being able to retrieve it.

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
${BUILDDIR}/onak -b -c $1 delete 0x94FA372B2DA8B985
if ! ${BUILDDIR}/onak -c $1 get 0x94FA372B2DA8B985 2>&1 | \
	grep -q 'Key not found'; then
	echo "* Did not correctly delete key"
	exit 1
fi

exit 0
