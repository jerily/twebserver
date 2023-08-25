# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindTCL
-------

This module finds if Tcl is installed and determines where the include
files and libraries are.  It also determines what the name of the
library is.  This code sets the following variables:

::

  TCL_FOUND              = Tcl was found
  TCL_LIBRARY            = path to Tcl library (tcl tcl80)
  TCL_INCLUDE_PATH       = path to where tcl.h can be found
  TCL_TCLSH              = path to tclsh binary (tcl tcl80)

::

   => they were only useful for people writing Tcl/Tk extensions.
   => these libs are not packaged by default with Tcl/Tk distributions.
      Even when Tcl/Tk is built from source, several flavors of debug libs
      are created and there is no real reason to pick a single one
      specifically (say, amongst tcl84g, tcl84gs, or tcl84sgx).
      Let's leave that choice to the user by allowing him to assign
      TCL_LIBRARY to any Tcl library, debug or not.
   => this ended up being only a Win32 variable, and there is a lot of
      confusion regarding the location of this file in an installed Tcl/Tk
      tree anyway (see 8.5 for example). If you need the internal path at
      this point it is safer you ask directly where the *source* tree is
      and dig from there.
#]=======================================================================]

if(TCLSH_VERSION_STRING)
  set(TCL_TCLSH_VERSION "${TCLSH_VERSION_STRING}")
else()
  get_filename_component(TCL_TCLSH_PATH "${TCL_TCLSH}" PATH)
  get_filename_component(TCL_TCLSH_PATH_PARENT "${TCL_TCLSH_PATH}" PATH)
  string(REGEX REPLACE
    "^.*tclsh([0-9]\\.*[0-9]).*$" "\\1" TCL_TCLSH_VERSION "${TCL_TCLSH}")
endif()

get_filename_component(TCL_INCLUDE_PATH_PARENT "${TCL_INCLUDE_PATH}" PATH)

#get_filename_component(TCL_LIBRARY_PATH "${TCL_LIBRARY}" PATH)
#get_filename_component(TCL_LIBRARY_PATH_PARENT "${TCL_LIBRARY_PATH}" PATH)
#string(REGEX REPLACE
#  "^.*tcl([0-9]\\.*[0-9]).*$" "\\1" TCL_LIBRARY_VERSION "${TCL_LIBRARY}")

if (NAVISERVER)
  SET(TCL_POSSIBLE_LIB_PATHS "${NAVISERVER}/lib")
endif()

if (TCL_INCLUDE_PATH_PARENT)
  SET(TCL_POSSIBLE_LIB_PATHS "${TCL_POSSIBLE_LIB_PATHS}" "${TCL_INCLUDE_PATH_PARENT}/lib")
endif()

if (TCL_TCLSH_PATH_PARENT)
  SET(TCL_POSSIBLE_LIB_PATHS "${TCL_POSSIBLE_LIB_PATHS}" "${TCL_TCLSH_PATH_PARENT}/lib")
endif()

set(TCL_POSSIBLE_LIB_PATHS ${TCL_POSSIBLE_LIB_PATHS}
        "/usr/local/lib"
        "/usr/lib"
 )

set(TCL_POSSIBLE_LIB_PATH_SUFFIXES
        tcl8.7
        tcl8.6
        tcl8.5
        tcl8.4
)

if(WIN32)
  get_filename_component(
    ActiveTcl_CurrentVersion
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\ActiveState\\ActiveTcl;CurrentVersion]"
    NAME)
  set(TCL_POSSIBLE_LIB_PATHS ${TCL_POSSIBLE_LIB_PATHS}
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\ActiveState\\ActiveTcl\\${ActiveTcl_CurrentVersion}]/lib"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Scriptics\\Tcl\\8.6;Root]/lib"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Scriptics\\Tcl\\8.5;Root]/lib"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Scriptics\\Tcl\\8.4;Root]/lib"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Scriptics\\Tcl\\8.3;Root]/lib"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Scriptics\\Tcl\\8.2;Root]/lib"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Scriptics\\Tcl\\8.0;Root]/lib"
    "$ENV{ProgramFiles}/Tcl/Lib"
    "C:/Program Files/Tcl/lib"
    "C:/Tcl/lib"
    )
endif()

find_library(TCL_LIBRARY
  NAMES
  tcl
  tcl${TCL_LIBRARY_VERSION} tcl${TCL_TCLSH_VERSION}
  tcl87 tcl8.7 tcl87t tcl8.7t
  tcl86 tcl8.6 tcl86t tcl8.6t
  tcl85 tcl8.5
  tcl84 tcl8.4
  tcl83 tcl8.3
  tcl82 tcl8.2
  tcl80 tcl8.0
  PATHS ${TCL_POSSIBLE_LIB_PATHS}
  PATH_SUFFIXES ${TCL_POSSIBLE_LIB_PATH_SUFFIXES}
        NO_DEFAULT_PATH
  )

set(TCL_FRAMEWORK_INCLUDES)
if(Tcl_FRAMEWORKS)
  if(NOT TCL_INCLUDE_PATH)
    foreach(dir ${Tcl_FRAMEWORKS})
      set(TCL_FRAMEWORK_INCLUDES ${TCL_FRAMEWORK_INCLUDES} ${dir}/Headers)
    endforeach()
  endif()
endif()

set(TCL_POSSIBLE_INCLUDE_PATHS
  "${TCL_LIBRARY_PATH_PARENT}/include"
  "${TCL_INCLUDE_PATH}"
  ${TCL_FRAMEWORK_INCLUDES}
  "${TCL_TCLSH_PATH_PARENT}/include"
  )

set(TCL_POSSIBLE_INCLUDE_PATH_SUFFIXES
  include/tcl${TCL_LIBRARY_VERSION}
  include/tcl8.7
  include/tcl8.6
  include/tcl8.5
  include/tcl8.4
  include/tcl8.3
  include/tcl8.2
  include/tcl8.0
  )

if(WIN32)
  set(TCL_POSSIBLE_INCLUDE_PATHS ${TCL_POSSIBLE_INCLUDE_PATHS}
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\ActiveState\\ActiveTcl\\${ActiveTcl_CurrentVersion}]/include"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Scriptics\\Tcl\\8.6;Root]/include"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Scriptics\\Tcl\\8.5;Root]/include"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Scriptics\\Tcl\\8.4;Root]/include"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Scriptics\\Tcl\\8.3;Root]/include"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Scriptics\\Tcl\\8.2;Root]/include"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Scriptics\\Tcl\\8.0;Root]/include"
    "$ENV{ProgramFiles}/Tcl/include"
    "C:/Program Files/Tcl/include"
    "C:/Tcl/include"
    )
endif()

find_path(TCL_INCLUDE_PATH
  NAMES tcl.h
  HINTS ${TCL_POSSIBLE_INCLUDE_PATHS}
  PATH_SUFFIXES ${TCL_POSSIBLE_INCLUDE_PATH_SUFFIXES}
  )

mark_as_advanced(
  TCL_INCLUDE_PATH
  TCL_LIBRARY
  )
