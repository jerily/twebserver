# Router-level Middleware

There are two types of router-level middleware procs in twebserver:
enter and leave. The enter proc is called before the matched route handler
is called and the leave proc is called after the matched
route handler has executed.

The enter proc has access to the context and request dictionaries.
The leave proc has access to the context, request, and response dictionaries.

The current middleware function can end the request-response cycle
by returning 0 i.e. ```return 0```.

Router-level middleware is bound to an instance of
a router:
    
```tcl
set router [::twebserver::create_router]

proc example_enter {ctx req} {
    puts "entering example"
}

proc example_leave {ctx req resp} {
    puts "leaving example"
}

::twebserver::add_middleware \
  -enter_proc example_enter \
  -leave_proc example_leave \
  $router
```
