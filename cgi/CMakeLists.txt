# CGI
add_executable(add add.c)
target_link_libraries(add libonak)
add_executable(gpgwww gpgwww.c ../stats.c)
target_link_libraries(gpgwww libonak)
add_executable(hashquery hashquery.c)
target_link_libraries(hashquery libonak)
add_executable(lookup lookup.c)
target_link_libraries(lookup libonak)
