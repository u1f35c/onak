# No pkg-config support in Berkeley DB, so try to find it manually

set(BDB_PREFIX "" CACHE PATH "path ")

find_path(BDB_INCLUDE_DIR db.h
	PATHS ${BDB_PREFIX}/include /usr/include /usr/local/include)

find_library(BDB_LIBRARY NAMES db
	PATHS ${BDB_PREFIX}/lib /usr/lib /usr/local/lib)

if(BDB_INCLUDE_DIR AND BDB_LIBRARY)
	get_filename_component(BDB_LIBRARY_DIR ${BDB_LIBRARY} PATH)
	set(BDB_FOUND TRUE)
endif()

if(BDB_FOUND)
	if(NOT BDB_FIND_QUIETLY)
		MESSAGE(STATUS "Found Berkeley DB: ${BDB_LIBRARY}")
	endif()
elseif(BDB_FOUND)
	if(BDB_FIND_REQUIRED)
		message(FATAL_ERROR "Could not find Berkeley DB")
	endif()
endif()
