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
wget http://prdownloads.sourceforge.net/tcl/tcl9.0b1-src.tar.gz
tar -xzvf tcl9.0b1-src.tar.gz
cd tcl9.0b1/unix
./configure --enable-threads
make
make install
```

### Build the twebserver extension
```
wget https://github.com/jerily/twebserver/archive/refs/tags/v1.47.25.tar.gz
tar -xzf v1.47.25.tar.gz
cd twebserver-1.47.25
mkdir build
cd build
# change "TCL_LIBRARY_DIR" and "TCL_INCLUDE_DIR" to the correct paths
cmake .. \
  -DTCL_LIBRARY_DIR=/usr/local/lib \
  -DTCL_INCLUDE_DIR=/usr/local/include
make
make install
```

### Or you can try your luck with docker

See [Docker directory](../docker/) for building and running twebserver on an Alpine Linux image.