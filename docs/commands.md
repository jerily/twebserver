
## TCL Commands

### High-Level Commands

* **::twebserver::create_server** *config_dict* *request_processor_proc* *?thread_init_script?*
    - returns a handle to a server, see [Server Configuration](config.md) for configuration parameters
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
      See [Routing](routing.md) for more information.
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
      See [Middleware](middleware.md) for more information.
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

* **::twebserver::get_form** *request_dict*
    - parses a form from a request dictionary
    The returned dictionary includes the following:
      - **fields** - a dictionary of fields
      - **multiValueFields** - a dictionary of fields (with multiple values)
      - **files** - a dictionary of files
  ```tcl
  set form_dict [::twebserver::get_form $request_dict]
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

#### Encode/Decode URIs

* **:twebserver::encode_uri_component** *string*
    - encodes a string for use in a URI
* **::twebserver::decode_uri_component** *string* *encoding_name*
    - decodes a string from a URI
* **::twebserver::encode_query** *query_string*
    - encodes a query string

#### Base64

* **::twebserver::base64_encode** *bytes*
    - encodes a string in base64
* **::twebserver::base64_decode** *base64_encoded_string*
    - decodes a base64 encoded string

#### Cookies

* **::twebserver::parse_cookie** *cookie_string*
    - parses a cookie string into a dictionary
* **::twebserver::add_header** *header_name* *header_value*
* **::twebserver::add_cookie** *?-path path_value?* *?-domain domain_value?* *?-samesite samesite_value?* *?-httponly?* *?-maxage seconds?* *cookie_name* *cookie_value*

#### Crypto

Use [tink-tcl](https://github.com/jerily/tink-tcl) for cryptographic APIs.
These commands are provided for convenience. 

* **::twebserver::random_bytes** *num_bytes*
    - generates random bytes of length ```num_bytes```
* **::twebserver::sha1** *bytes*
    - generates a sha1 hash of ```bytes```
* **::twebserver::sha256** *bytes*
    - generates a sha256 hash of ```bytes```
* **::twebserver::sha512** *bytes*
    - generates a sha412 hash of ```bytes```

#### Hex

* **::twebserver::hex_encode** *bytes*
    - encodes a string in hex
* **::twebserver::hex_decode** *hex_encoded_string*
    - decodes a hex encoded string
