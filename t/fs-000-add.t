#!/bin/sh
# Check we can add a key successfully with the fs backend.

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
if [ ! -e db/key/2D/A8/2DA8B985/94FA372B2DA8B985 ]; then
	echo Did not correctly add key using fs backend.
	exit 1
fi

exit 0
