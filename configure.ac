AC_PREREQ(2.50)
AC_INIT([onak],[0.3.0],[noodles-onak@earth.li])

AC_CONFIG_HEADER(config.h)

AC_PROG_CC

AC_C_BIGENDIAN

AC_ARG_ENABLE(backend,AC_HELP_STRING([--enable-backend=<backend>],[Choose the backend database to use. Defaults to db3.]), [], [enable_backend="db3"])

AC_MSG_CHECKING([which key database backend to use])
AC_MSG_RESULT([$enable_backend])
AC_CHECK_FILE(keydb_$enable_backend.c, ,AC_MSG_ERROR([non existent key database backend $enable_backend]))

if test "x$enable_backend" = "xdb3"
then
	AC_CHECK_LIB(db3, db_env_create,,
		AC_MSG_ERROR([cannot compile DB3 backend without libdb3]))
else if test "x$enable_backend" = "xpg"
then
	AC_CHECK_LIB(pq, PQsetdbLogin,,
		AC_MSG_ERROR([cannot compile PostgreSQL backend without libpq]))
fi
fi

AC_SUBST(DBTYPE, $enable_backend)

AC_CONFIG_FILES(Makefile)

AC_OUTPUT
