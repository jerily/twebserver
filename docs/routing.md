# Routing

Routing refers to determining how an application responds
to a client request to a particular endpoint,
which is a path and a specific HTTP request method (GET, POST, and so on).

Each route can have one or more handler functions,
which are executed when the route is matched.

Route definition takes the following structure:

```tcl
::twebserver::add_route ROUTER METHOD PATH HANDLER
```

Where:

* ```ROUTER``` is an instance of a router created with ```::twebserver::create_router```
* ```METHOD``` is an HTTP request method, e.g. GET, POST, PUT, DELETE, PATCH, and OPTIONS.
* ```PATH``` is a path on the server e.g. ```/example/:user_id/view```
* ```HANDLER``` is the handler function executed when the route is matched e.g. ```get_example_handler```

The following examples illustrate defining simple routes.
See the [Dictionaries documentation](ctx_req_res_dict.md) for more information on the context, request, and response dictionaries.

Respond with "hello world" for requests to the URL ```/example```
```tcl
proc example_handler {ctx req} {
    set text "hello world"
    return [::twebserver::build_response 200 text/plain $text]
}

::twebserver::add_route $router GET /example example_handler
```

Respond to POST request on the URL ```/example```
```tcl
proc example_handler {ctx req} {
    set text "Got a POST request"
    return [::twebserver::build_response 200 text/plain $text]
}

::twebserver::add_route $router POST /example example_handler
```

### Route Methods

A route method is derived from one of the HTTP methods,
i.e. GET, POST, PUT, DELETE, PATCH, and OPTIONS,

### Route Paths

Route paths, in combination with a request method,
define the endpoints at which requests can be made.
Route paths can be strings, string patterns, or regular expressions.

### Route Parameters

Route parameters are named URL segments that are used to capture
the values specified at their position in the URL. The captured values
are populated in the pathParameters section of the request object ```req```,
with the name of the route parameter specified in the path as their
respective keys.

To define routes with route parameters,
simply specify the route parameters in the path of the route as
shown below.

```tcl
proc example_handler {ctx req} {
    set user_id [::twebserver::get_path_param $req user_id]
    set text "hello user $user_id"
    return [::twebserver::build_response 200 text/plain $text]
}

::twebserver::add_route $router GET /example/:user_id/view example_handler
```

### Route Handlers

Route handlers can be in the form of a proc that accepts
the context ```ctx``` and the request ```req``` dictionaries
and returns a response ```res``` dictionary.

```tcl
proc example_handler {ctx req} {
    set user_id [::twebserver::get_path_param $req user_id]
    set text "hello user $user_id"
    return [::twebserver::build_response 200 text/plain $text]
}
```

### Guard Proc List

A guard proc list is a list of procs that are executed before the route handler.
The guard procs should accept the context ```ctx``` and the request ```req``` dictionaries
and return 0 or 1. If a guard proc returns 0, the route handler is not executed.

```tcl
proc is_logged_in {ctx req} {
    if { [dict exists $req session is_logged_in] } {
        return $req
    }
    return -code error -options [::twebserver::build_response 401 text/plain "unauthorized"]
}

proc example_handler {ctx req} {
    set user_id [::twebserver::get_path_param $req user_id]
    set text "hello user $user_id"
    return [::twebserver::build_response 200 text/plain $text]
}

::twebserver::add_route \
    -guard_proc_list [list is_logged_in] \
    $router GET /example/:user_id/view example_handler
```