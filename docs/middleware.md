# Middleware and guards

In twebserver 2.0.0, the native C command `::twebserver::invoke_handler`
composes application middleware around tpathexp route handlers. The deprecated
`::twebserver::add_middleware` compatibility command uses the same native
implementation. Application hooks remain ordinary Tcl command prefixes.

Middleware is a list of `{enter leave}` command-prefix pairs. Enter hooks accept
`ctx req` and return the updated request. Leave hooks accept `ctx req res` and
return the updated response. Either hook can be an empty list. Enter hooks run
in registration order; leave hooks run in reverse order.

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

set middleware {{::session_enter ::session_leave}}
$router add GET /dashboard \
    [list ::twebserver::invoke_handler ::dashboard $middleware {::require_login}] \
    -strict true
```

This code runs in the worker after loading both packages and creating `$router`.
Guards run after middleware enters and before the handler, and can return an
updated request. The native wrapper supports intentional-response errors via
`return -code error -options $response`, where `$response` includes `statusCode`
and `body`. On these responses, it runs the leave hooks for layers already
entered (including the layer whose enter hook aborted), then tpathexp validates
the response. Later middleware and the handler are skipped.

Unexpected Tcl errors propagate to the connection callback and become logged
500 responses; leave hooks are not run after those errors. Malformed response
dictionaries also become 500 responses. HEAD bodies are cleared, including on
error responses.

Middleware wraps matched handlers. Automatically generated tpathexp 404/405
responses do not pass through these hooks. Register an explicit catch-all to
apply middleware to custom not-found responses. See the
[complete example](../examples/example-best-with-router.tcl) for sessions,
rate limiting, guards, and error handlers together.
