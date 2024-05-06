#!/bin/bash

export SCRIPT_DIR=$(dirname $(readlink -f $0))
export PROJECT_DIR=$SCRIPT_DIR
export PROJECT_LOCAL_DIR=$PROJECT_DIR/local
export LD_LIBRARY_PATH=$PROJECT_LOCAL_DIR/lib:$PROJECT_LOCAL_DIR/lib64


mkdir -p $PROJECT_DIR/certs/
cd $PROJECT_DIR/certs/
$PROJECT_LOCAL_DIR/bin/openssl req -x509 \
        -newkey rsa:4096 \
        -keyout key.pem \
        -out cert.pem \
        -sha256 \
        -days 3650 \
        -nodes \
        -subj "/C=CY/ST=Cyprus/L=Home/O=none/OU=CompanySectionName/CN=localhost/CN=www.example.com"
cd ..
exec $PROJECT_LOCAL_DIR/bin/tclsh9.0 $PROJECT_DIR/examples/example-best-with-router.tcl
