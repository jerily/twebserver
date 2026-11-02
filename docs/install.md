# Installation Guide

The extension depends on OpenSSL (3.0.2 or later) and TCL (8.6.13 or later).

### Install Dependencies

To install the packages on Debian/Ubuntu-based systems:
```bash
sudo apt-get install cmake libssl-dev
```

To install the packages on Amazon Linux/Redhat/Fedora/CentOS-based systems
```bash
sudo yum install cmake openssl-devel
```

To install the packages on MacOS:
```bash
brew install cmake openssl@3
```

### Install TCL

To install TCL with threads from source:
```bash
# Download and extract the source
# https://www.tcl.tk/software/tcltk/download.html
wget http://prdownloads.sourceforge.net/tcl/tcl9.0b3-src.tar.gz
tar -xzvf tcl9.0b3-src.tar.gz
cd tcl9.0b3/unix
./configure
make
make install
```

### Build the twebserver extension

From this source checkout:

```bash
cmake -S . -B build
# For a custom Tcl install, also pass:
# -DTCL_LIBRARY_DIR=/your/tcl/lib -DTCL_INCLUDE_DIR=/your/tcl/include
cmake --build build
cmake --install build
```

Version 2.0.0 installs into `lib/twebserver2.0.0`. The server itself does not
require tpathexp.

### Install routing support for examples and tests

Build [tpathexp](https://github.com/jerily/tpathexp) 1.1.0 or later against the
same Tcl ABI as twebserver:

```bash
git clone --branch v1.1.0 https://github.com/jerily/tpathexp.git ../tpathexp
cmake -S ../tpathexp -B ../tpathexp/build
cmake --build ../tpathexp/build
cmake --install ../tpathexp/build
```

When several Tcl versions are installed, select matching `TCL_INCLUDE_PATH`,
`TCL_LIBRARY`, `TCL_STUB_LIBRARY`, and `TCL_TCLSH` in the tpathexp configuration.
A Tcl 8 extension cannot be loaded into Tcl 9 or vice versa.

For tests using an uninstalled tpathexp build:

```bash
cmake -S . -B build -DTPATHEXP_LIBRARY_DIR="$(pwd)/../tpathexp/build"
cmake --build build
ctest --test-dir build --output-on-failure
```

For examples using uninstalled builds, put both package directories on
`TCLLIBPATH` (a Tcl list), using the shell for the Tcl version you built:

```bash
TCLLIBPATH="{$PWD/build} {$PWD/../tpathexp/build}" tclsh9.0 examples/example-best-with-router.tcl
```

### Or you can try your luck with docker

See [Docker directory](../docker/) for building and running twebserver on an Alpine Linux image.
