cmake_minimum_required(VERSION 3.22.1)
project(twebserver VERSION 1.47.53 LANGUAGES CXX C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(TARGET twebserver)
set(CMAKE_C_STANDARD   11)
set(CMAKE_C_STANDARD_REQUIRED true)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(OpenSSL 3.0.2 REQUIRED)     # OPENSSL_INCLUDE_DIR OPENSSL_LIBRARIES
find_package(TCL 8.6.13 REQUIRED)  # TCL_INCLUDE_PATH TCL_LIBRARY
find_package(Threads REQUIRED)
find_program(TCL_TCLSH
        NAMES
        tclsh90 tclsh9.0
        tclsh86 tclsh8.6
        tclsh
        PATHS
        ${TCL_INCLUDE_PATH}/../bin
        ${TCL_INCLUDE_PATH}/../../bin
        NO_DEFAULT_PATH
)

message(STATUS "TCL_INCLUDE_PATH: ${TCL_INCLUDE_PATH}")
message(STATUS "TCL_LIBRARY: ${TCL_LIBRARY}")

#set(CMAKE_VERBOSE_MAKEFILE ON)
#set(CMAKE_C_FLAGS  "-DNDEBUG -DTCL_THREADS -DVERSION=${PROJECT_VERSION} ${CMAKE_C_FLAGS}")
#set(CMAKE_C_FLAGS  "-g -DPURIFY -DDEBUG -fsanitize=address -DNDEBUG -DTCL_THREADS -DVERSION=${PROJECT_VERSION} ${CMAKE_C_FLAGS}")

add_compile_options(-Wall -Wextra -Wpedantic)
add_compile_definitions(TCL_THREADS VERSION=${PROJECT_VERSION})

if ("${ADDRESS_SANITIZER}" STREQUAL "ON")
    add_compile_options(-fPIC -g -fsanitize=undefined -fsanitize=address)
    add_link_options(-fsanitize=undefined -fsanitize=address)
endif ()

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(CMAKE_C_FLAGS "-g -DDEBUG ${CMAKE_C_FLAGS}")
else()
    # NDEBUG to not generate code for assert
    add_compile_definitions(NDEBUG)
endif ()

set(CMAKE_CTEST_ARGUMENTS "--verbose")
set(CMAKE_CTEST_ARGUMENTS "--output-on-failure")
enable_testing()
add_test(NAME AllUnitTests
        COMMAND ${TCL_TCLSH} ${CMAKE_CURRENT_SOURCE_DIR}/tests/all.tcl
)
set_tests_properties(AllUnitTests
        PROPERTIES ENVIRONMENT TCLLIBPATH=${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_target(shell ${CMAKE_COMMAND} -E env TCLLIBPATH=${CMAKE_CURRENT_BINARY_DIR} ${TCL_TCLSH}
        USES_TERMINAL
        DEPENDS ${TARGET})



add_library(twebserver SHARED src/library.c src/base64.c src/base64/cencode.c src/base64/cdecode.c
        src/router.c
        src/conn.c
        src/common.c
        src/request.c
        src/crypto.c
        src/path_regexp/path_regexp.c
        src/form.c
        src/https.c
        src/http.c
        src/return.c
)
set_target_properties(twebserver PROPERTIES POSITION_INDEPENDENT_CODE ON)

include_directories(${TCL_INCLUDE_PATH} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(twebserver PRIVATE ${OPENSSL_LIBRARIES} ${TCL_LIBRARY} Threads::Threads)
#target_link_options(twebserver PUBLIC -fsanitize=address)
get_filename_component(TCL_LIBRARY_PATH "${TCL_LIBRARY}" PATH)

install(TARGETS ${TARGET}
        LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${TARGET}${PROJECT_VERSION}
)

configure_file(pkgIndex.tcl.in pkgIndex.tcl @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgIndex.tcl
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${TARGET}${PROJECT_VERSION}
)
