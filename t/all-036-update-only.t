#!/bin/sh
# Check we can't submit a new key when update_only is set

set -e

cd ${WORKDIR}
cp $1 update-only.ini
echo update_only=true >> update-only.ini
${BUILDDIR}/onak -b -c update-only.ini add < ${TESTSDIR}/../keys/noodles.key || true
rm update-only.ini
if ! ${BUILDDIR}/onak -c $1 get 0x94FA372B2DA8B985 2>&1 | \
	grep -q 'Key not found'; then
	echo "* Did not correctly error on update-only key"
	exit 1
fi

exit 0
