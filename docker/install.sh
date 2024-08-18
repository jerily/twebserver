#!/bin/bash

set -eo pipefail # exit on error

export SCRIPT_DIR=$(dirname $(readlink -f $0))
INSTALL_DIR=$SCRIPT_DIR/local
echo "Installing to $INSTALL_DIR"

BUILD_DIR=$SCRIPT_DIR/build
mkdir -p $BUILD_DIR

BUILD_LOG_DIR=$BUILD_DIR/logs
mkdir -p $BUILD_LOG_DIR
export LD_LIBRARY_PATH=$INSTALL_DIR/lib:$INSTALL_DIR/lib64
export PKG_CONFIG_PATH=$INSTALL_DIR/lib/pkgconfig

# openssl
if true; then
curl -L -O --output-dir $BUILD_DIR/ https://www.openssl.org/source/openssl-3.2.1.tar.gz
tar -xvf $BUILD_DIR/openssl-3.2.1.tar.gz -C $BUILD_DIR
cd $BUILD_DIR/openssl-3.2.1
./Configure --prefix=$INSTALL_DIR > $BUILD_LOG_DIR/openssl-configure.log 2>&1
make install > $BUILD_LOG_DIR/openssl-install.log 2>&1
fi

# tcl
if true; then
curl -L -O --output-dir $BUILD_DIR http://prdownloads.sourceforge.net/tcl/tcl9.0b2-src.tar.gz
tar -xvf $BUILD_DIR/tcl9.0b2-src.tar.gz -C $BUILD_DIR
cd $BUILD_DIR/tcl9.0b2/unix
./configure  --prefix=$INSTALL_DIR > $BUILD_LOG_DIR/tcl-configure.log 2>&1
make install > $BUILD_LOG_DIR/tcl-install.log 2>&1
fi

# twebserver
if true; then
curl -L -o twebserver-1.47.51.tar.gz --output-dir $BUILD_DIR https://github.com/jerily/twebserver/archive/refs/tags/v1.47.51.tar.gz
tar -xvf $BUILD_DIR/twebserver-1.47.51.tar.gz -C $BUILD_DIR
cd $BUILD_DIR/twebserver-1.47.51
mkdir build
cd build
# change "TCL_LIBRARY_DIR" and "TCL_INCLUDE_DIR" to the correct paths
cmake .. \
  -DTCL_LIBRARY_DIR=$INSTALL_DIR/lib \
  -DTCL_INCLUDE_DIR=$INSTALL_DIR/include \
  -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR \
  -DCMAKE_PREFIX_PATH=$INSTALL_DIR/ > $BUILD_LOG_DIR/twebserver-configure.log 2>&1
make install > $BUILD_LOG_DIR/twebserver-install.log 2>&1
fi