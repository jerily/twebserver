# tws

TCL Web Server (HTTPS) Extension

## Build
```
git clone https://github.com/jerily/tws.git
cd tws
mkdir build
cd build
cmake ..
make
make install
```

## Try it out
```
tclsh ../examples/example.tcl
curl -k https://localhost:4433
curl -k -X POST -H "Content-Type: application/json" --data '{"message": "hello world"}' https://localhost:4433
curl -k -X POST -H 'content-type: image/jpeg' --data-binary @../examples/Google_2015_logo.png https://localhost:4433
```