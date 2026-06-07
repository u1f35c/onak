#!/bin/sh
# Check we can retrieve a key by keyid

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
if ! ${BUILDDIR}/sixdegrees -c $1 2> /dev/null | \
	grep -q -- 'Degree 1:.*1'; then
	echo "* Could not get sixdegrees of connection."

	exit 1
fi

exit 0
