AC_PREREQ(2.50)
AC_INIT([onak],[0.3.0],[noodles-onak@earth.li])
AC_CONFIG_SRCDIR(onak.c)
AC_CONFIG_HEADER(config.h)

AC_PROG_CC

AC_C_BIGENDIAN

AC_ARG_ENABLE(backend,AC_HELP_STRING([--enable-backend=<backend>],[Choose the backend database to use. Defaults to db4.]), [], [enable_backend="db4"])

AC_MSG_CHECKING([which key database backend to use])
AC_MSG_RESULT([$enable_backend])
AC_CHECK_FILE([$srcdir/keydb_$enable_backend.c], ,AC_MSG_ERROR([non existent key database backend $enable_backend]))

if test "x$enable_backend" = "xdb4"
then
	AC_CHECK_HEADER(db.h, have_db_h="yes", have_db_h="no")
	AC_MSG_CHECKING(for libdb version in db.h)
	printf "#include <db.h>\nDB_VERSION_MAJOR DB_VERSION_MINOR\n" >conftest.c
	set `eval $ac_cpp conftest.c | egrep '^ *[[0-9]] *'`; v="$1"; vv="$2"
	AC_MSG_RESULT($v.$vv)
	if test "$v" -ne 4; then
		AC_MSG_ERROR([   * onak requires libdb version 4])
	fi
	for db in "db-$v.$vv" "db$v.$vv" "db-$v" "db$v" "db"; do
		AC_MSG_CHECKING(for db_create in lib$db)
		oldLIBS="$LIBS"
		LIBS="$LIBS -l$db"
		AC_TRY_LINK([#include <db.h>], db_create(0, 0, 0),
			have_libdb="yes", have_libdb="no")
		AC_MSG_RESULT($have_libdb)
		if test "$have_libdb" != "no"; then break; fi
		LIBS="$oldLIBS"
	done
	if test "$have_libdb" = "no" -o "$have_db_h" = "no"; then
		AC_MSG_ERROR(libdb not found.)
	fi
	AC_DEFINE(HAVE_LIBDB, 1, [libdb found])
else if test "x$enable_backend" = "xpg"
then
	AC_CHECK_LIB(pq, PQsetdbLogin,,
		AC_MSG_ERROR([cannot compile PostgreSQL backend without libpq]))
fi
fi

AC_SUBST(DBTYPE, $enable_backend)

AC_CONFIG_FILES(Makefile)

AC_OUTPUT
