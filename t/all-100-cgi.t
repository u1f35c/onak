#!/bin/sh
# Check we can retrieve a key using the lookup CGI

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
ln -s $1 ${WORKDIR}/onak.ini
trap cleanup exit
cleanup () {
	rm ${WORKDIR}/onak.ini
}
if ! XDG_CONFIG_HOME=${WORKDIR} ${BUILDDIR}/cgi/lookup "op=index&search=0x2DA8B985" 2> /dev/null | \
	grep -q -- 'Jonathan McDowell'; then
	echo "* Could not lookup key using lookup CGI."

	exit 1
fi

exit 0
