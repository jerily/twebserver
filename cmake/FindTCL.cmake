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

set(TCL_POSSIBLE_LIB_PATHS ${TCL_LIBRARY_DIR})

set(TCL_POSSIBLE_LIB_PATH_SUFFIXES
        tcl8.7
        tcl8.6
        tcl8.5
        tcl8.4
)

find_library(TCL_LIBRARY
  NAMES
  tcl
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

set(TCL_POSSIBLE_INCLUDE_PATHS
        "${TCL_INCLUDE_DIR}"
  "${TCL_LIBRARY_PATH_PARENT}/include"
  )

set(TCL_POSSIBLE_INCLUDE_PATH_SUFFIXES
  include/tcl8.7
  include/tcl8.6
  include/tcl8.5
  include/tcl8.4
  include/tcl8.3
  include/tcl8.2
  include/tcl8.0
  )

find_path(TCL_INCLUDE_PATH
  NAMES tcl.h
  HINTS ${TCL_POSSIBLE_INCLUDE_PATHS}
  PATH_SUFFIXES ${TCL_POSSIBLE_INCLUDE_PATH_SUFFIXES}
        NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH NO_CMAKE_SYSTEM_PATH
  )

mark_as_advanced(
  TCL_INCLUDE_PATH
  TCL_LIBRARY
  )
