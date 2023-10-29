# Router-level Middleware

There are two types of router-level middleware procs in twebserver:
enter and leave. The enter proc is called before the matched route handler
is called and the leave proc is called after the matched
route handler has executed.

The enter proc has access to the context and request dictionaries.
The leave proc has access to the context, request, and response dictionaries.

In the future, the current middleware function will be able to
end the request-response cycle by returning 0 i.e. ```return 0```.
Otherwise, it should return to continue processing the request.

Router-level middleware is bound to an instance of
a router:
    
```tcl
set router [::twebserver::create_router]

proc example_enter {ctx req} {
    puts "entering example"
    return $req
}

proc example_leave {ctx req res} {
    puts "leaving example"
    put $res
}

::twebserver::add_middleware \
  -enter_proc example_enter \
  -leave_proc example_leave \
  $router
```

See [tsession](https://github.com/jerily/tsession) for an example of router-level middleware.