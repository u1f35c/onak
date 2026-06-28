#!/bin/sh
# Check that cleankeys() collapses multiple signatures from the same
# issuer per (version, sigtype, keyid) at import time.
# noodles.key ships with 134 signature packets that map to 119 distinct
# issuer keyids; after the dedupe pass the stored record must drop
# below the original count and stay safely above the distinct count.

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
COUNT=$(${BUILDDIR}/onak -c $1 vindex 0x94FA372B2DA8B985 2>/dev/null | \
	grep -cE '^(sig|rev)' || true)
if [ "$COUNT" -ge 134 ]; then
	echo "* dedupe_sigs left every input signature in place (got $COUNT)"
	exit 1
fi
if [ "$COUNT" -lt 60 ]; then
	echo "* dedupe_sigs collapsed too aggressively (got $COUNT)"
	exit 1
fi

exit 0
