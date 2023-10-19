cmake_minimum_required(VERSION 3.22.1)
project(twebserver VERSION 1.47.4 LANGUAGES CXX C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(TARGET twebserver)
set(CMAKE_C_STANDARD   11)
set(CMAKE_C_STANDARD_REQUIRED true)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(OpenSSL 3.0.2 REQUIRED)     # OPENSSL_INCLUDE_DIR OPENSSL_LIBRARIES
find_package(TCL EXACT 8.6.13 REQUIRED)  # TCL_INCLUDE_PATH TCL_LIBRARY

message(STATUS "TCL_INCLUDE_PATH: ${TCL_INCLUDE_PATH}")
message(STATUS "TCL_LIBRARY: ${TCL_LIBRARY}")

#set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_C_FLAGS  "-DTCL_THREADS -DVERSION=${PROJECT_VERSION} ${CMAKE_C_FLAGS}")


add_library(twebserver SHARED src/library.c src/base64.c src/base64/cencode.c src/base64/cdecode.c
        src/router.c
        src/conn.c
        src/common.c
        src/request.c
        src/path_regexp/path_regexp.c)
set_target_properties(twebserver PROPERTIES POSITION_INDEPENDENT_CODE ON)

include_directories(${TCL_INCLUDE_PATH} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(twebserver PRIVATE ${OPENSSL_LIBRARIES} ${TCL_LIBRARY})
get_filename_component(TCL_LIBRARY_PATH "${TCL_LIBRARY}" PATH)

install(TARGETS ${TARGET}
        LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${TARGET}${PROJECT_VERSION}
)

configure_file(pkgIndex.tcl.in pkgIndex.tcl @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgIndex.tcl
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${TARGET}${PROJECT_VERSION}
)
