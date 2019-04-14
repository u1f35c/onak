cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
project(onak VERSION 0.5.0 LANGUAGES C)

include(FindPkgConfig)
include(GNUInstallDirs)
include(TestBigEndian)
# Fall back for earlier versions of CMake which lack RUNSTATEDIR
if ("x${CMAKE_INSTALL_FULL_RUNSTATEDIR}" STREQUAL "x")
	set(CMAKE_INSTALL_FULL_RUNSTATEDIR
		${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/run)
endif()

# Configuration options from the user
set(DBTYPE "dynamic" CACHE STRING
	"Configure the default database backend to use" )
option(KEYD
	"Enable the key daemon to handle communication with the key database"
	ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
TEST_BIG_ENDIAN(WORDS_BIGENDIAN)

# Pick up a git based version number for development builds
find_package(Git)
if (GIT_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
	EXECUTE_PROCESS(COMMAND ${GIT_EXECUTABLE} describe --tags --dirty
		OUTPUT_VARIABLE GIT_VERSION
		OUTPUT_STRIP_TRAILING_WHITESPACE)
	string(REPLACE "onak-" "" VERSION ${GIT_VERSION})
else()
	set(VERSION ${PROJECT_VERSION})
endif()

# Core objects
add_library(libonak STATIC armor.c charfuncs.c cleankey.c cleanup.c decodekey.c
	getcgi.c hash.c keyarray.c keyid.c keyindex.c ll.c log.c marshal.c
	mem.c merge.c onak-conf.c parsekey.c photoid.c sigcheck.c sendsync.c
	sha1x.c wordlist.c)
set(LIBONAK_LIBRARIES "")

# Ideally use Nettle, fall back to our own md5/sha1 routines otherwise
pkg_check_modules(NETTLE nettle)
if (NETTLE_FOUND)
	set(HAVE_NETTLE true)
	target_include_directories(libonak SYSTEM PUBLIC ${NETTLE_INCLUDE_DIRS})
	LIST(APPEND LIBONAK_LIBRARIES ${NETTLE_LIBRARIES})
else()
	target_sources(libonak PRIVATE md5.c sha1.c)
endif()

# Backends

# These have no dependencies and can always be compiled
set(BACKENDS "file" "fs" "stacked")

# DB4 backend (add check for existence)
LIST(APPEND BACKENDS db4)
set(BACKEND_db4_LIBS db-5.3)

# HKP backend - needs libcurl
pkg_check_modules(CURL libcurl)
if (CURL_FOUND)
	LIST(APPEND BACKENDS hkp)
	set(BACKEND_hkp_INC ${CURL_INCLUDE_DIRS})
	set(BACKEND_hkp_LIBS ${CURL_LIBRARIES})
endif()

# PostgreSQL backend - needs libpq
pkg_check_modules(POSTGRESQL libpq)
if (POSTGRESQL_FOUND)
	LIST(APPEND BACKENDS pg)
	set(BACKEND_pg_INC ${POSTGRESQL_INCLUDE_DIRS})
	set(BACKEND_pg_LIBS ${POSTGRESQL_LIBRARIES})
endif()

# keyd backend - can be disabled entirely
if (KEYD STREQUAL "ON")
	LIST(APPEND BACKENDS keyd)

	add_executable(keyd keyd.c)
	target_link_libraries(keyd libonak)
	add_executable(keydctl keydctl.c onak-conf.c)
	target_link_libraries(keydctl libonak)
	target_compile_definitions(keydctl PRIVATE
		CONFIGDIR="${CMAKE_INSTALL_FULL_SYSCONFDIR}")

	pkg_check_modules(SYSTEMD libsystemd)
	if (SYSTEMD_FOUND)
		set(HAVE_SYSTEMD true)
		target_include_directories(keyd SYSTEM PUBLIC
			${SYSTEMD_INCLUDE_DIRS})
		target_link_libraries(keyd ${SYSTEMD_LIBRARIES})
	endif()

	install(TARGETS keydctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
	install(TARGETS keyd RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
	install(FILES keyd.8 keydctl.8
		DESTINATION ${CMAKE_INSTALL_MANDIR}/man8/)
endif()


# Now we have the DB type confirmed we can tidy up the libonak options

if (DBTYPE STREQUAL "dynamic")
	LIST(APPEND LIBONAK_LIBRARIES "dl")
	foreach(BACKEND IN LISTS BACKENDS)
		add_library(keydb_${BACKEND} SHARED keydb_${BACKEND}.c)
		target_include_directories(keydb_${BACKEND} SYSTEM PUBLIC
			${BACKEND_${BACKEND}_INC})
		target_link_libraries(keydb_${BACKEND} libonak
			${BACKEND_${BACKEND}_LIBS})
		install(TARGETS keydb_${BACKEND} LIBRARY DESTINATION
			${CMAKE_INSTALL_LIBDIR}/onak/backends/)
	endforeach(BACKEND)
else()
	list (FIND BACKENDS ${DBTYPE} _index)
	if (${_index} LESS 0)
		message(FATAL_ERROR "${DBTYPE} is not a supported DB backend.")
	endif()

	LIST(APPEND LIBONAK_LIBRARIES ${BACKEND_${DBTYPE}_LIBS})
endif()

# For onak-conf.o compilation
target_compile_definitions(libonak PRIVATE
	CONFIGDIR="${CMAKE_INSTALL_FULL_SYSCONFDIR}"
	DBINIT=keydb_${DBTYPE}_init)

# DB Backend related options are known, so finish off libonak configuration
target_sources(libonak PRIVATE keydb_${DBTYPE}.c)
target_link_libraries(libonak ${LIBONAK_LIBRARIES})

# Executables start here

# Swiss Army tool
add_executable(onak onak.c)
target_link_libraries(onak libonak)

# CGI
add_executable(add add.c)
target_link_libraries(add libonak)
add_executable(gpgwww gpgwww.c stats.c)
target_link_libraries(gpgwww libonak)
add_executable(hashquery hashquery.c)
target_link_libraries(hashquery libonak)
add_executable(lookup lookup.c)
target_link_libraries(lookup libonak)

# Tools that operate on the key DB
add_executable(maxpath maxpath.c stats.c)
target_link_libraries(maxpath libonak)
add_executable(sixdegrees sixdegrees.c stats.c)
target_link_libraries(sixdegrees libonak)
add_executable(wotsap wotsap.c)
target_link_libraries(wotsap libonak)

# Stand alone tools
add_executable(splitkeys splitkeys.c)
target_link_libraries(splitkeys libonak)
add_executable(stripkey stripkey.c)
target_link_libraries(stripkey libonak)

install(TARGETS onak splitkeys RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES onak.1 splitkeys.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1/)

# Build files that have substitutions in them
include_directories(${CMAKE_BINARY_DIR})
configure_file("${CMAKE_SOURCE_DIR}/build-config.h.in"
	"${CMAKE_BINARY_DIR}/build-config.h" @ONLY)

configure_file("${CMAKE_SOURCE_DIR}/onak.ini.in"
	"${CMAKE_BINARY_DIR}/onak.ini" @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/onak.ini
	DESTINATION ${CMAKE_INSTALL_SYSCONFDIR})

configure_file("${CMAKE_SOURCE_DIR}/onak-mail.pl.in"
	"${CMAKE_BINARY_DIR}/onak-mail.pl" @ONLY)
install(PROGRAMS ${CMAKE_BINARY_DIR}/onak-mail.pl
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/onak/)
install(FILES onak-mail.pl.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8/)

# Basic unit tests
enable_testing()
add_test(NAME syntaxtest COMMAND perl -cw ${CMAKE_BINARY_DIR}/onak-mail.pl)
add_test(NAME sanitytests COMMAND ${CMAKE_SOURCE_DIR}/runtests)