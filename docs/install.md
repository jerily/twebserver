# Installation Guide

The extension depends on OpenSSL (3.0.2 or later) and TCL (8.6.13).

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
cd tcl8.6.13/unix
./configure --enable-threads
make
make install
```

### Build the twebserver extension
```
wget https://github.com/jerily/twebserver/archive/refs/tags/v1.47.4.tar.gz
tar -xzf v1.47.4.tar.gz
export TWS_DIR=$(pwd)/twebserver-1.47.4
cd ${TWS_DIR}
mkdir build
cd build
# change "TCL_LIBRARY_DIR" and "TCL_INCLUDE_DIR" to the correct paths
cmake .. \
  -DTCL_LIBRARY_DIR=/usr/local/lib \
  -DTCL_INCLUDE_DIR=/usr/local/include
make
make install
```
