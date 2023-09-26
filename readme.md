# twebserver

TCL Web Server (HTTPS) Extension

## Getting Started

The extension depends on OpenSSL (3.0.2 or later) and TCL (8.6.13).

### Install Dependencies

To install the packages on Debian/Ubuntu-based systems:
```bash
sudo apt-get install libssl-dev
```

To install the packages on Amazon Linux/Redhat/Fedora/CentOS-based systems
```bash
sudo yum install openssl-devel
```

### Build the library
```
wget https://github.com/jerily/twebserver/archive/refs/tags/v1.47.1.tar.gz
tar -xzf v1.47.1.tar.gz
export TWS_DIR=$(pwd)/twebserver-1.47.1
cd ${TWS_DIR}
mkdir build
cd build
cmake ..
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
tclsh ../examples/example-with-req-resp.tcl
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
tclsh ../examples/example-best-with-native-threads.tcl
```

## Benchmark
```
go install github.com/parkghost/gohttpbench@latest
# with keepalive
gohttpbench -v 10 -n 100000 -c 10 -t 10 -k "https://localhost:4433/example?a=1&b=2"
# without keepalive
gohttpbench -v 10 -n 100000 -c 10 -t 10 "https://localhost:4433/example?a=1&b=2"
```

## TCL Commands

* **::twebserver::create_server** *config_dict* *request_processor_proc* *?thread_init_script?*
    - returns a handle to a server, see [docs/config.md](docs/config.md) for configuration parameters
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
* **::twebserver::destroy_server** *handle*
  - destroys a server
  ```tcl
  ::twebserver::destroy_server $server_handle
  ```
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
