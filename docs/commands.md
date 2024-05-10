
## TCL Commands

### High-Level Commands

* **::twebserver::create_server** *?with_router?* *config_dict* *request_processor_proc* *thread_init_script*
    - returns a handle to a server, see [Server Configuration](config.md) for configuration parameters
    - when ```with_router``` option is specified, it skips the execution of the ```request_processor_proc``` and directly
  invokes the router
  ```tcl
  set server_handle [::twebserver::create_server [dict create] process_conn {...}]
  ```
* **::twebserver::add_context** *?-verify_client?* *?-cafile file?* *?-cadir path?* *handle* *hostname* *key_file* *cert_file*
    - adds an SSL context to a server (supports multiple certificates for different hosts)
    - the flag ```-verify_client``` can be used to enable client verification
    - the flag ```-cafile``` should be used to specify a CA file when client verification is enabled
    - the flag ```-cadir``` should be used to specify a CA directory when client verification is enabled
  ```tcl
  ::twebserver::add_context $server_handle localhost "../certs/host1/key.pem" "../certs/host1/cert.pem"
  ::twebserver::add_context $server_handle www.example.com "../certs/host2/key.pem" "../certs/host2/cert.pem"
  ```
* **::twebserver::listen_server** *?-http?* *?-num_threads n?* *?-host hostname?* *handle* *port*
    - starts listening for HTTPS on a port. if the flag ```-http``` is specified, then the server will listen for HTTP on the port.
        The option ```-num_threads``` can be used to specify the number of threads to use for the listener.
          The option ```-host``` can be used to specify the hostname to listen on.
  ```tcl
  ::twebserver::listen_server $server_handle 4433
  ::twebserver::listen_server -http -num_threads 4 $server_handle 8080
  ::twebserver::listen_server -host www.example.com $server_handle 443
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

* **::twebserver::get_form** *request_dict*
    - parses a form from a request dictionary
      The returned dictionary includes the following:
        - **fields** - a dictionary of fields
        - **multiValueFields** - a dictionary of fields (with multiple values)
        - **files** - a dictionary of files
  ```tcl
  set form_dict [::twebserver::get_form $request_dict]
  ```

* **::twebserver::get_path_param** *request_dict* *param_name* *?return_list?*
    - returns a path parameter from a request dictionary, if ```return_list``` is true, then a list of values is returned
  ```tcl
  set param_value [::twebserver::get_path_param $request_dict $param_name]
  ```

* **::twebserver::get_query_param** *request_dict* *param_name* *?return_list?*
    - returns a query parameter from a request dictionary, if ```return_list``` is true, then a list of values is returned
  ```tcl
    set param_value [::twebserver::get_query_param $request_dict $param_name]
    ```

* **::twebserver::get_header** *request_dict* *header_name* *?return_list?*
    - returns a header from a request dictionary, if ```return_list``` is true, then a list of values is returned
  ```tcl
  set header_value [::twebserver::get_header $request_dict $header_name]
  ```
* **::twebserver::get_param** *?-return_list?* *?-from_path?* *?-from_query?* *?-from_header?* *request_dict* "param_or_header_name*
    - returns a parameter or header from a request dictionary,
  it first checks for a path parameter, then a query parameter, then a header.
    If ```return_list``` is true, then a list of values is returned.
  The flags ```-from_path```, ```-from_query```, and ```-from_header``` can be used
  to restrict where to look for the parameter or header.
  ```tcl
  set param_value [::twebserver::get_param $request_dict $param_or_header_name]
  ```

* **::twebserver::build_response** *?-return_file?* status_code mimetype body
    - builds a response dictionary, when ```-return_file``` is specified, the body is treated as a file path
  ```tcl
  set response_dict [::twebserver::build_response 200 text/plain "hello world"]
  set response_dict [::twebserver::build_response -return_file 200 image/png plume.png]
  ```

* **::twebserver::wait_signal**
    - an alternative to vwait that waits for a signal (SIGINT or SIGTERM) to be sent to the server
  ```tcl
  ::twebserver::wait_signal
  ```

### Low-level Commands

* **::twebserver::return_response** *handle* *response_dict* *?encoding?*
    - sends a response to a connection (to be used without routing)
  ```tcl
  ::twebserver::return_response $handle $response_dict
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
* **::twebserver::add_cookie** *?-path path_value?* *?-domain domain_value?* *?-samesite samesite_value?* *?-httponly?* *?-insecure* *?-maxage seconds?* *cookie_name* *cookie_value*

#### Query String

* **::twebserver::parse_query** *query_string* *?encoding?*
    - parses a query string into a dictionary

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
    - generates a sha512 hash of ```bytes```

#### Hex

* **::twebserver::hex_encode** *bytes*
    - encodes a string in hex
* **::twebserver::hex_decode** *hex_encoded_string*
    - decodes a hex encoded string

#### IP

* **::twebserver::ipv6_to_ipv4** *ipv6_address*
    - converts an ipv6 address to an ipv4 address if it can be mapped

#### Info

* **::twebserver::get_rootdir** *?server_handle?*
    - returns the root directory of the current server or the specified server

* **::twebserver::info_conn** *handle*
    - returns information about a connection:
      - ```request``` - the request dictionary
      - ```server``` - the server handle