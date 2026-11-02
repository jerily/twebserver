
## TCL Commands

### High-Level Commands

* **::twebserver::create_server** *?-with_router?* *config_dict* *request_processor_proc* *thread_init_script*
    - returns a handle to a server, see [Server Configuration](config.md) for configuration parameters
    - `-with_router` is deprecated and accepted for compatibility; all requests use the normal callback path
    - the ```request_processor_proc``` should accept two arguments: ```context_dict``` and ```request_dict```.
      It must send its response with `::twebserver::return_response`; returning a dictionary alone does not send it.
      See the [Dictionaries documentation](ctx_req_res_dict.md) for more information on the context and request dictionaries.

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

Routing is supplied by [tpathexp](routing.md). The following commands are
implemented in twebserver's C extension:

* **::twebserver::process_conn** *router context request* adapts the request to
  tpathexp, dispatches it, and sends the response. Unexpected dispatch errors
  become logged 500 responses; all HEAD response bodies are cleared. Bind the
  router with `interp alias {} process_conn {} ::twebserver::process_conn $router`
  to use this as the server callback.
* **::twebserver::invoke_handler** *handler middleware guards request context params*
  runs enter hooks, guards, a `{ctx req}` handler, and reverse-order leave hooks.
  Register `[list ::twebserver::invoke_handler $handler $middleware $guards]`
  as a tpathexp route handler; tpathexp supplies the last three arguments.
  See [Middleware](middleware.md) for the hook and early-response contracts.

### Deprecated router compatibility commands

These Tcl wrappers load tpathexp 1.1.0 or later on first use. They do not use a
bundled matcher. New code should use tpathexp directly.

* **::twebserver::create_router** *?-command_name command?* *?varname?* creates a
  router callback and returns its handle. If a variable is supplied, it is
  read-only; unsetting it destroys the router and its callback commands.
* **::twebserver::add_route** *?-name name?* *?-guard_proc_list list?* *?-prefix?*
  *?-nocase?* *?-strict?* *router method path handler* preserves the old
  `{ctx req}` handler signature. `-name` populates `ctx route_name`.
* **::twebserver::add_middleware** *?-enter_proc prefix?* *?-leave_proc prefix?*
  *router* composes the existing enter/leave signatures. Middleware registered
  after routes still applies to those routes.
* **::twebserver::info_routes** *router* returns the registered route metadata.
  Regex patterns now use tpathexp's POSIX syntax.

The shim translates bare `*`, boolean flags, and guard lists. See
[Migration notes](routing.md#migrating-from-1x) for matching differences.

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

* **::twebserver::build_redirect** *status_code* *location*
    - builds a redirect response dictionary
  ```tcl
  set response_dict [::twebserver::build_redirect 301 "https://www.example.com"]
  set response_dict [::twebserver::build_redirect 302 "/"]
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

* **::twebserver::get_rootdir**
  - returns the root directory of the current server

* **::twebserver::get_config_dict**
  - returns the config dict of the current server

* **::twebserver::info_conn** *handle*
    - returns information about a connection:
      - ```request``` - the request dictionary
      - ```server``` - the server handle