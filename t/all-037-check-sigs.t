#!/bin/sh
# Check that signatures are only added when they can be verified

set -e

cd ${WORKDIR}
cp $1 check-sigs.ini

trap cleanup exit
cleanup () {
	rm check-sigs.ini
}
echo verify_signatures=true >> check-sigs.ini

${BUILDDIR}/onak -b -c check-sigs.ini add < ${TESTSDIR}/../keys/noodles-ecc.key || true
if ${BUILDDIR}/onak -c $1 vindex 0x9026108FB942BEA4 2>&1 | \
	grep -q '0x94FA372B2DA8B985'; then
	echo "* Did not correctly strip unknown signatures"
	exit 1
fi

${BUILDDIR}/onak -b -c check-sigs.ini add < ${TESTSDIR}/../keys/noodles.key || true

${BUILDDIR}/onak -b -c check-sigs.ini add < ${TESTSDIR}/../keys/noodles-ecc.key || true
if ! ${BUILDDIR}/onak -c $1 vindex 0x9026108FB942BEA4 2>&1 | \
	grep -q '0x94FA372B2DA8B985'; then
	echo "* Did not correctly verify new signature"
	exit 1
fi

exit 0
