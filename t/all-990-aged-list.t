#!/bin/sh
# Check that 'onak aged' lists the fingerprint of a key older than the
# requested cutoff. The shipped noodles.key was created in 2008, so any
# reasonable age cutoff returns it.

set -e

# Backends that do not implement iterate_keys cannot answer this.
if [ "$2" = "fs" ] || [ "$2" = "hkp" ]; then
	exit 0
fi
# Keyring backend is read-only; skip.
if [ "$2" = "keyring" ]; then
	exit 0
fi

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
if ! ${BUILDDIR}/onak -c $1 aged 1y 2>/dev/null | \
	grep -q -i '^0E3A94C3E83002DAB88CCA1694FA372B2DA8B985$'; then
	echo "* 'onak aged 1y' did not list the expected fingerprint"
	exit 1
fi

exit 0
