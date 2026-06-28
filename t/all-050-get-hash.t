#!/bin/sh
# Check we can index a key by SKS hash

set -e

# Backends should really support this, but the file one is as simple as
# possible, so doesn't. Skip the test for it.
if [ "$2" = "file" ]; then
	exit 0
fi

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
# Discover the SKS hash of the cleaned, deduped key as actually stored,
# rather than assuming the hash of the wire form: cleankeys() collapses
# multiple signatures from the same issuer per (version, sigtype) before
# storage, so the on-disk hash differs from the submitted one.
HASH=$(${BUILDDIR}/onak -c $1 -s index 0x94FA372B2DA8B985 2>/dev/null | \
	sed -n 's/.*Key hash = //p')
if [ -z "$HASH" ]; then
	echo "* Failed to discover SKS hash of stored key"
	exit 1
fi
if ! ${BUILDDIR}/onak -c $1 hget "$HASH" 2> /dev/null | \
	grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----'; then
	echo "* Did not correctly retrieve key by SKS hash $HASH"
	exit 1
fi

exit 0
