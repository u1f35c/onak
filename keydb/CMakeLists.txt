# Key database backends

# These have no dependencies and can always be compiled
set(BACKENDS "dummy" "file" "fs" "keyring" "stacked")

# DB4 backend (add check for existence)
find_package(BDB)
if (BDB_FOUND)
	LIST(APPEND BACKENDS db4)
	set(BACKEND_db4_LIBS db)
endif()

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

	add_executable(onak-keyd keyd.c)
	target_link_libraries(onak-keyd libonak)
	add_executable(onak-keydctl keydctl.c ../onak-conf.c)
	target_link_libraries(onak-keydctl libonak)
	target_compile_definitions(onak-keydctl PRIVATE
		CONFIGDIR="${CMAKE_INSTALL_FULL_SYSCONFDIR}")

	if (SYSTEMD_FOUND)
		target_include_directories(onak-keyd SYSTEM PUBLIC
			${SYSTEMD_INCLUDE_DIRS})
		target_link_libraries(onak-keyd ${SYSTEMD_LIBRARIES})
	endif()

	install(TARGETS onak-keydctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
	install(TARGETS onak-keyd RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
	install(FILES onak-keyd.8 onak-keydctl.8
		DESTINATION ${CMAKE_INSTALL_MANDIR}/man8/)
endif()

if (DBTYPE STREQUAL "dynamic")
	foreach(BACKEND IN LISTS BACKENDS)
		add_library(keydb_${BACKEND} SHARED keydb_${BACKEND}.c)
		target_include_directories(keydb_${BACKEND} SYSTEM PUBLIC
			${BACKEND_${BACKEND}_INC})
		target_link_libraries(keydb_${BACKEND} libonak
			${BACKEND_${BACKEND}_LIBS})
		install(TARGETS keydb_${BACKEND} LIBRARY DESTINATION
			${CMAKE_INSTALL_LIBDIR}/onak/backends/)
	endforeach(BACKEND)
endif()
