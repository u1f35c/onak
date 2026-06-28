#!/bin/sh
# Check that cap_uids_per_key drops UIDs beyond the cap on import.
# The test key carries 50 UIDs; with the default cap of 32 we expect
# exactly 32 to survive.

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/manyuids.key
COUNT=$(${BUILDDIR}/onak -c $1 index 0x2AFDD17797642257 2>/dev/null | \
	grep -c '@example.org' || true)
if [ "$COUNT" != "32" ]; then
	echo "* cap_uids_per_key did not trim to 32 UIDs (got $COUNT)"
	exit 1
fi

exit 0
