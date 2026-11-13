# Middleware and guards

Middleware execution is supplied by tpathexp 1.2.0. twebserver's middleware
implementation has been removed; the deprecated `::twebserver::add_middleware`
command forwards registrations to the native tpathexp router.

Register router hooks with `$router add_middleware -enter_proc prefix
-leave_proc prefix`. Routes also accept `-enter_proc` and `-leave_proc`.
Enter hooks accept `ctx req` and return the updated request. Leave hooks accept
`ctx req res` and return the updated response. Either hook can be an empty list;
a router layer requires at least one nonempty hook. All hooks support command
prefixes. Router enters run in registration order, then the route enter and
handler. The route leave runs first, followed by router leaves in reverse order.

```tcl
proc session_enter {ctx req} {
    dict set req session [dict create id 1234567890]
    return $req
}
proc session_leave {ctx req res} {
    return [::twebserver::add_cookie -maxage 3600 \
        $res session_id [dict get $req session id]]
}
proc require_login {ctx req} {
    if {![dict exists $req session user_id]} {
        return -code error -options \
            [::twebserver::build_response 401 text/plain "unauthorized"]
    }
    return $req
}
proc dashboard {ctx req} {
    return [::twebserver::build_response 200 text/plain "Dashboard"]
}

$router add_middleware -enter_proc ::session_enter -leave_proc ::session_leave
$router add GET /dashboard \
    [list ::twebserver::invoke_handler ::dashboard] \
    -enter_proc ::require_login -strict true
```

This code runs in the worker after loading both packages and creating `$router`.
A route enter hook can act as a guard after router enters and return an updated
request. Native tpathexp dispatch supports intentional-response errors via
`return -code error -options $response`, where `$response` includes `statusCode`
and `body`. On these responses, it runs the leave hooks for layers already
entered (including the layer whose enter hook aborted), then tpathexp validates
the response. Later middleware and the handler are skipped.

Unexpected Tcl errors propagate to the connection callback and become logged
500 responses; leave hooks are not run after those errors. Malformed response
dictionaries also become 500 responses. HEAD bodies are cleared, including on
error responses.

Router middleware also wraps automatic 404/405 responses. Route hooks only run
for a matching method and path. Matching happens before hooks run, so changing
`req path` or `req method` in an enter hook does not select a different route. See the
[complete example](../examples/example-best-with-router.tcl) for sessions,
rate limiting, guards, and error handlers together.
