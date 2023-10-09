# twebserver

TCL Web Server (HTTPS) Extension

## Getting Started

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
wget https://github.com/jerily/twebserver/archive/refs/tags/v1.47.3.tar.gz
tar -xzf v1.47.3.tar.gz
export TWS_DIR=$(pwd)/twebserver-1.47.3
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
### Generate certs

To use the library, you will need to generate a key and certificate.  You can do this with the following commands:
```bash
# First go into the directory where the certificate should be stored.
openssl genrsa -out key.pem
openssl req -new -key key.pem -out csr.pem
openssl x509 -req -days 9999 -in csr.pem -signkey key.pem -out cert.pem
```

Alternatively, you can use the following command:
```bash
# First go into the directory where the certificate should be stored.
openssl req -x509 \
        -newkey rsa:4096 \
        -keyout key.pem \
        -out cert.pem \
        -sha256 \
        -days 3650 \
        -nodes \
        -subj "/C=CY/ST=Cyprus/L=Home/O=none/OU=CompanySectionName/CN=localhost/CN=www.example.com"
```

## Try it out without threads

Run the example:
```bash
tclsh8.6 ../examples/example-with-req-resp.tcl
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

Run the example:
```bash
tclsh8.6 ../examples/example-best-with-native-threads.tcl
```

## Benchmark

Install go and gohttpbench:
```
brew install go
go install github.com/parkghost/gohttpbench@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

With keepalive (example-best-with-native-threads.tcl - uses parse_conn/return_conn): 
```
gohttpbench -v 10 -n 100000 -c 10 -t 10 -k "https://localhost:4433/example?a=1&b=2"

Concurrency Level:      10
Time taken for tests:   1.51 seconds
Complete requests:      100000
Failed requests:        0
HTML transferred:       23700000 bytes
Requests per second:    66290.23 [#/sec] (mean)
Time per request:       0.151 [ms] (mean)
Time per request:       0.015 [ms] (mean, across all concurrent requests)
HTML Transfer rate:     15342.21 [Kbytes/sec] received
```

Without keepalive (example-best-with-native-threads.tcl - uses parse_conn/return_conn):
```
gohttpbench -v 10 -n 100000 -c 10 -t 10 "https://localhost:4433/example?a=1&b=2"

Concurrency Level:      10
Time taken for tests:   10.00 seconds
Complete requests:      35832
Failed requests:        0
HTML transferred:       8313024 bytes
Requests per second:    3583.20 [#/sec] (mean)
Time per request:       2.791 [ms] (mean)
Time per request:       0.279 [ms] (mean, across all concurrent requests)
HTML Transfer rate:     811.80 [Kbytes/sec] received
```

## TCL Commands

### High-Level Commands

* **::twebserver::create_server** *config_dict* *request_processor_proc* *?thread_init_script?*
    - returns a handle to a server, see [Server Configuration](docs/config.md) for configuration parameters
  ```tcl
  set server_handle [::twebserver::create_server [dict create] process_conn]
  ```
* **::twebserver::add_context** *handle* *hostname* *key_file* *cert_file*
  - adds an SSL context to a server (supports multiple certificates for different hosts)
  ```tcl
  ::twebserver::add_context $server_handle localhost "../certs/host1/key.pem" "../certs/host1/cert.pem"
  ::twebserver::add_context $server_handle www.example.com "../certs/host2/key.pem" "../certs/host2/cert.pem"
  ```
* **::twebserver::listen_server** *handle* *port*
    - starts listening on a port
  ```tcl
  ::twebserver::listen_server $server_handle 4433
  ```
* **::twebserver::destroy_server** *handle*
  - destroys a server
  ```tcl
  ::twebserver::destroy_server $server_handle
  ```
* **::twebserver::create_router**
  - returns a handle to a router and creates a request_processor_proc
like the one accepted in ```create_server``` command
  ```tcl
  set router [::twebserver::create_router]
  ```
* **::twebserver::add_route** *?-prefix?* *?-nocase?* *?-strict?* *router* *method* *path* *handler_proc*
  - adds a route to a router, the handler_proc should accept two arguments: ```context_dict``` and ```request_dict```.
    See [Routing](docs/routing.md) for more information.
  ```tcl
  proc example_handler {ctx req} {
    set response_dict [dict create]
    dict set response_dict statusCode 200
    dict set response_dict body "hello world"
    return $response_dict
  }
  ::twebserver::add_route $router GET /example example_handler
  ```

* **::twebserver::add_middleware** *?-enter_proc enter_proc_name?* *?-leave_proc leave_proc_name?* *router*
  - adds middleware to a router, the enter_proc_name should accept two arguments: ```context_dict``` and ```request_dict```.
    The leave_proc_name should accept three arguments: ```context_dict```, ```request_dict```, and ```response_dict```.
    See [Middleware](docs/middleware.md) for more information.
    ```tcl
    proc example_enter {ctx req} {
      puts "entering example"
      return $req
    }
    proc example_leave {ctx req res} {
      puts "leaving example"
      return $res
    }
    ::twebserver::add_middleware \
      -enter_proc example_enter \
      -leave_proc example_leave \
      $router
    ```
### Medium-level Commands

* **::twebserver::parse_conn** *conn* *encoding_name*
  - reads a connection and parses the request to a dictionary.
    The dictionary includes the following:
    - **httpMethod** - GET, POST, PUT, DELETE, etc
    - **url** - the url
    - **version** - HTTP/1.1
    - **path** - the path
    - **queryString** - the query string
    - **queryStringParameters** - a dictionary of query string parameters
    - **multiValueQueryStringParameters** - a dictionary of query string parameters (with multiple values)
    - **headers** - a dictionary of headers
    - **multiValueHeaders** - a dictionary of headers (with multiple values)
    - **isBase64Encoded** - whether the body is base64 encoded
    - **body** - the body
  ```tcl
  set request_dict [::twebserver::parse_conn $conn]
  ```
* **::twebserver::return_conn** *conn* *response_dict*
  - returns a response dictionary to a connection.
    The response dictionary should include the following:
    - **statusCode** - the status code
    - **headers** - a dictionary of headers
    - **multiValueHeaders** - a dictionary of headers (with multiple values)
    - **isBase64Encoded** - whether the body is base64 encoded
    - **body** - the body
  ```tcl
  ::twebserver::return_conn $conn $response_dict
  ```

### Low-level Commands

* **::twebserver::read_conn** *conn*
    - reads a connection, low-level command, prefer **::twebserver::parse_conn**
  ```tcl
  set request [::twebserver::read_conn $conn]
  ```
* **::twebserver::write_conn** *conn* *text*
    - writes to a connection, low-level command, prefer **::twebserver::return_conn**
  ```tcl
  ::twebserver::write_conn $conn $response
  ```
* **::twebserver::keepalive_conn** *conn*
  - marks the connection as keep-alive, low-level command, can be used when **::twebserver::parse_conn** is not used
  ```tcl
  ::twebserver::keepalive_conn $conn
  ```
* **::twebserver::close_conn** *conn* *?force_shutdown?*
    - closes a connection unless it is marked as keep-alive,
      force_shutdown will force the connection to close no matter what
  ```tcl
  ::twebserver::close_conn $conn
  ```
* **::twebserver::parse_request** *request* *encoding_name*
    - parses a request into a dictionary, low-level command, prefer **::twebserver::parse_conn**
  ```tcl
  set request_dict [::twebserver::parse_request $request]
  ```

### Utility Commands

* **:twebserver::encode_uri_component** *string*
  - encodes a string for use in a URI
* **::twebserver::decode_uri_component** *string* *encoding_name*
  - decodes a string from a URI
* **::twebserver::encode_query** *query_string*
  - encodes a query string
* **::twebserver::base64_encode** *bytes*
  - encodes a string in base64
* **::twebserver::base64_decode** *base64_encoded_string*
  - decodes a base64 encoded string
