#!/bin/sh
# Check trying to submit a blacklisted key fails

set -e

cd ${WORKDIR}
echo 0E3A94C3E83002DAB88CCA1694FA372B2DA8B985 > ${WORKDIR}/blacklist
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key || true
echo '#' >  ${WORKDIR}/blacklist
if ! ${BUILDDIR}/onak -c $1 get 0x94FA372B2DA8B985 2>&1 | \
	grep -q 'Key not found'; then
	echo "* Did not correctly error on non-existent key"
	exit 1
fi

exit 0
