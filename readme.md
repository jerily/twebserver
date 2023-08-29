# tws

TCL Web Server (HTTPS) Extension

## Generate certs
```
openssl genrsa -out key.pem
openssl req -new -key key.pem -out csr.pem
openssl x509 -req -days 9999 -in csr.pem -signkey key.pem -out cert.pem
```

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

## Try it out without threads

Run the example:
```bash
tclsh ../examples/example.tcl
```

Try a few requests:
```bash
# simple get request
curl -k https://localhost:4433
# json post request
curl -k -X POST -H "Content-Type: application/json" --data '{"message": "hello world"}' https://localhost:4433
# isBase64Encoded
curl -k -X POST -H 'content-type: image/jpeg' --data-binary @../examples/Google_2015_logo.png https://localhost:4433
# multivalue headers
curl -k -X POST -H "Content-Type: application/json" -H "X-Custom-Header: asdf" -H "X-Custom-Header: qwerty" --data '{"message": "hello world"}' https://localhost:4433
# query string parameters
curl -k -X POST -H "Content-Type: application/json" -H "X-Custom-Header: this is a test" -H "X-Custom-Header: hello world" --data '{"message": "hello world"}' 'https://localhost:4433/example?a=1&b=2&c=this+is+a+test'
# multivalue query string parameters
curl -k -X POST -H "Content-Type: application/json" -H "X-Custom-Header: this is a test" -H "X-Custom-Header: hello world" --data '{"message": "hello world"}' 'https://localhost:4433/exampl
e?a=1&b=2&c=this+is+a+test&c=blah+blah'
```

## Try it out with threads

Install TCL "Thread" package:
```bash
wget -O thread2.8.8.tar.gz https://sourceforge.net/projects/tcl/files/Thread%20Extension/2.8.8/thread2.8.8.tar.gz/download
tar -xzvf thread2.8.8.tar.gz
cd thread2.8.8/unix
../configure --enable-threads
make
make install
```

Run the example:
```bash
tclsh ../examples/example-with-threads.tcl
```

## Benchmark
```
go install github.com/parkghost/gohttpbench@latest
gohttpbench -c 500 -t 10  "https://localhost:4433/example?a=1&b=2"
```

## TCL Commands

* **::twebserver::create_server** *config_dict* *init_proc*
    - returns a handle to a server
* **::twebserver::destroy_server** *handle*
    - destroys a server
* **::twebserver::listen_server** *handle* *port*
    - starts listening on a port
* **::twebserver::add_context** *handle* *hostname* *key_file* *cert_file*
    - adds an SSL context to a server (supports multiple certificates for different hosts)
* **::twebserver::read_conn** *conn*
    - reads a connection
* **::twebserver::write_conn** *conn* *text*
    - writes to a connection
* **::twebserver::close_conn** *conn*
    - closes a connection
* **::twebserver::parse_request** *request*
    - parses a request into a dictionary (includes headers, query, and body among other things)
* **:twebserver::encode_uri_component** *string*
    - encodes a string for use in a URI
* **::twebserver::decode_uri_component** *string* *encoding_name*
    - decodes a string from a URI
* **::twebserver::encode_query** *query_string*
    - encodes a query string
