#!/bin/sh
# Check we can add a key successfully with the file backend.

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
if [ ! -e db/0x2DA8B985 ]; then
	echo Did not correctly add key using file backend.
	exit 1
fi

exit 0
