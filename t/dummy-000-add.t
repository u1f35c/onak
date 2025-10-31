#!/bin/sh
# Check we can add a key "successfully" with the dummy backend.

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key

exit 0
