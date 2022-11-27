cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
project(onak VERSION 0.6.2 LANGUAGES C)

include(CheckSymbolExists)
include(FindPkgConfig)
include(GNUInstallDirs)
include(TestBigEndian)
# Fall back for earlier versions of CMake which lack RUNSTATEDIR
if ("x${CMAKE_INSTALL_FULL_RUNSTATEDIR}" STREQUAL "x")
	set(CMAKE_INSTALL_FULL_RUNSTATEDIR
		${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/run)
endif()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

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
	mem.c merge.c onak-conf.c parsekey.c photoid.c rsa.c sigcheck.c sendsync.c
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

# We need libhogweed and libgmp to be able to do more than hash calculations
pkg_check_modules(HOGWEED hogweed)
if (HOGWEED_FOUND)
	find_package(GMP)
endif()
if (GMP_FOUND)
	set(HAVE_CRYPTO true)
	target_include_directories(libonak SYSTEM PUBLIC
			${GMP_INCLUDE_DIRS} ${HOGWEED_INCLUDE_DIRS})
	LIST(APPEND LIBONAK_LIBRARIES ${GMP_LIBRARY} ${HOGWEED_LIBRARIES})

	set(CMAKE_REQUIRED_INCLUDES ${NETTLE_INCLUDE_DIRS})
	set(CMAKE_REQUIRED_LIBRARIES ${NETTLE_LIBRARIES} ${HOGWEED_LIBRARIES})
	# API change in later version of Nettle
	CHECK_SYMBOL_EXISTS(nettle_get_secp_256r1 "nettle/ecc-curve.h" HAVE_NETTLE_GET_SECP_256R1)
	CHECK_SYMBOL_EXISTS(nettle_get_secp_384r1 "nettle/ecc-curve.h" HAVE_NETTLE_GET_SECP_384R1)
	CHECK_SYMBOL_EXISTS(nettle_get_secp_521r1 "nettle/ecc-curve.h" HAVE_NETTLE_GET_SECP_521R1)
endif()

# Build files that have substitutions in them
include_directories(${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR})
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

# Key database backends
add_subdirectory(keydb)

# Now we have the DB type confirmed we can tidy up the libonak options

if (DBTYPE STREQUAL "dynamic")
	LIST(APPEND LIBONAK_LIBRARIES "dl")
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
target_sources(libonak PRIVATE keydb/keydb_${DBTYPE}.c)
target_link_libraries(libonak ${LIBONAK_LIBRARIES})

# CGI directory
add_subdirectory(cgi)

# Executables start here

# Swiss Army tool
add_executable(onak onak.c)
target_link_libraries(onak libonak)

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

# Basic unit tests
enable_testing()
add_test(NAME syntaxtest COMMAND perl -cw ${CMAKE_BINARY_DIR}/onak-mail.pl)
add_test(NAME sanitytests COMMAND ${CMAKE_SOURCE_DIR}/runtests)
