cmake_minimum_required(VERSION 3.22.1)
project(tws LANGUAGES CXX C)

set(TARGET tws)
set(CMAKE_C_STANDARD   11)
set(CMAKE_C_STANDARD_REQUIRED true)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

#set(CMAKE_VERBOSE_MAKEFILE ON)
#set(CMAKE_C_FLAGS  "-DDEBUG ${CMAKE_C_FLAGS}")

add_library(tws SHARED MODULE library.c)
set_target_properties(tws PROPERTIES POSITION_INDEPENDENT_CODE ON)

include(${CMAKE_CURRENT_LIST_DIR}/FindTCL.cmake)

target_link_libraries(tws PRIVATE ssl crypto ${TCL_LIBRARY})
get_filename_component(TCL_LIBRARY_PATH "${TCL_LIBRARY}" PATH)

install(TARGETS ${TARGET}
        LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${TARGET}
)
install(FILES pkgIndex.tcl
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${TARGET}
)
