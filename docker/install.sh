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
curl -L -O --output-dir $BUILD_DIR http://prdownloads.sourceforge.net/tcl/tcl9.0.0-src.tar.gz
tar -xvf $BUILD_DIR/tcl9.0.0-src.tar.gz -C $BUILD_DIR
cd $BUILD_DIR/tcl9.0.0/unix
./configure  --prefix=$INSTALL_DIR > $BUILD_LOG_DIR/tcl-configure.log 2>&1
make install > $BUILD_LOG_DIR/tcl-install.log 2>&1
fi

# tpathexp supplies routing for the examples; build against the same Tcl ABI.
git clone --depth 1 --branch v1.1.0 https://github.com/jerily/tpathexp.git "$BUILD_DIR/tpathexp"
cmake -S "$BUILD_DIR/tpathexp" -B "$BUILD_DIR/tpathexp-build" \
  -DBUILD_TESTING=OFF \
  -DTCL_INCLUDE_PATH="$INSTALL_DIR/include" \
  -DTCL_LIBRARY="$INSTALL_DIR/lib/libtcl9.0.so" \
  -DTCL_STUB_LIBRARY="$INSTALL_DIR/lib/libtclstub.a" \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" > "$BUILD_LOG_DIR/tpathexp-configure.log" 2>&1
cmake --build "$BUILD_DIR/tpathexp-build" > "$BUILD_LOG_DIR/tpathexp-build.log" 2>&1
cmake --install "$BUILD_DIR/tpathexp-build" > "$BUILD_LOG_DIR/tpathexp-install.log" 2>&1

# Build the checked-out twebserver 2.0.0 sources supplied by the Docker context.
cmake -S "$SCRIPT_DIR/twebserver" -B "$BUILD_DIR/twebserver-build" \
  -DTCL_LIBRARY_DIR="$INSTALL_DIR/lib" \
  -DTCL_INCLUDE_DIR="$INSTALL_DIR/include" \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DCMAKE_PREFIX_PATH="$INSTALL_DIR" > "$BUILD_LOG_DIR/twebserver-configure.log" 2>&1
cmake --build "$BUILD_DIR/twebserver-build" > "$BUILD_LOG_DIR/twebserver-build.log" 2>&1
cmake --install "$BUILD_DIR/twebserver-build" > "$BUILD_LOG_DIR/twebserver-install.log" 2>&1
