AC_PREREQ(2.50)
AC_INIT([onak],[0.4.0],[noodles-onak@earth.li])
AC_CONFIG_SRCDIR(onak.c)
AC_CONFIG_HEADER(config.h)

AC_PROG_CC
AC_PROG_CC_C99

AC_C_BIGENDIAN

m4_include([m4/ax_lib_nettle.m4])

AX_LIB_NETTLE(auto)

dnl We should always have these backends available.
backends="file fs keyd"

AC_CHECK_LIB(pq, PQsetdbLogin,[have_libpq="yes" backends="$backends pg"],have_libpq="no")

AC_CHECK_HEADER(db.h, have_db_h="yes", have_db_h="no")
AC_MSG_CHECKING(for libdb version in db.h)
printf "#include <db.h>\nDB_VERSION_MAJOR DB_VERSION_MINOR\n" >conftest.c
set `eval $ac_cpp conftest.c | egrep '^ *[[0-9]] *'`; v="$1"; vv="$2"
AC_MSG_RESULT($v.$vv)
if test "$v" -ge 4; then
	for db in "db-$v.$vv" "db$v.$vv" "db-$v" "db$v" "db"; do
		AC_MSG_CHECKING(for db_create in lib$db)
		oldLIBS="$LIBS"
		LIBS="$LIBS -l$db"
		db4libs="-l$db"
		AC_TRY_LINK([#include <db.h>], db_create(0, 0, 0),
			have_libdb="yes", have_libdb="no")
		AC_MSG_RESULT($have_libdb)
		LIBS="$oldLIBS"
		if test "$have_libdb" != "no"; then break; fi
	done
fi
if test "$have_libdb" = "yes" -a "$have_db_h" = "yes"; then
	AC_DEFINE(HAVE_LIBDB4, 1, [libdb found])
	backends="$backends db4"
fi

AC_MSG_CHECKING(available backends)
AC_MSG_RESULT($backends)

AC_ARG_ENABLE(backend,AC_HELP_STRING([--enable-backend=<backend>],[Choose the backend database to use. Defaults to dynamic.]), [], [enable_backend="dynamic"])

AC_ARG_ENABLE(keyd,AC_HELP_STRING([--enable-keyd],[Use keyd as the DB backend.]), [], [])

AC_MSG_CHECKING([which key database backend to use])
AC_MSG_RESULT([$enable_backend])
AC_CHECK_FILE([$srcdir/keydb_$enable_backend.c], ,AC_MSG_ERROR([non existent key database backend $enable_backend]))

if test "x$enable_backend" = "xdb4"
then
	if test "$have_libdb" = "no" -o "$have_db_h" = "no"; then
		AC_MSG_ERROR(libdb not found.)
	fi
	LIBS="$LIBS $db4libs"
else if test "x$enable_backend" = "xpg"
then
	if test "$have_libpq" = "no"; then
		AC_MSG_ERROR(libpq not found.)
	fi
	LIBS="$LIBS -lpq"
fi
fi

dnl If we are explicitly told which backend to use, only build that one.
if test "x$enable_backend" = "xdb4"
then
	backend="$enable_backend"
fi

AC_SUBST(DBTYPE, $enable_backend)
AC_SUBST(DB4LIBS, $db4libs)
AC_SUBST(KEYD, $enable_keyd)
AC_SUBST(BACKENDS, $backends)

AC_CONFIG_FILES(Makefile)

AC_OUTPUT
