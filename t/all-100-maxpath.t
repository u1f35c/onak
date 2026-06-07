#!/bin/sh
# Check we can retrieve a key by keyid

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
if ! ${BUILDDIR}/maxpath -c $1 2> /dev/null | \
	grep -q -- ' steps from '; then
	echo "* Could not get maximum path length"

	${BUILDDIR}/maxpath -c $1

	exit 1
fi

exit 0
