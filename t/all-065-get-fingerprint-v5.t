#!/bin/sh
# Check we can retrieve a key by key fingerprint

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/v5-test.key
if ! ${BUILDDIR}/onak -c $1 get 0x19347BC9872464025F99DF3EC2E0000ED9884892E1F7B3EA4C94009159569B54 2> /dev/null | \
	grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----'; then
	echo "* Did not correctly retrieve key by fingerprint."
	exit 1
fi

exit 0
