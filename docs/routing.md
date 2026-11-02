# Routing with tpathexp

Starting with twebserver 2.0.0, routing is supplied by the separate
[tpathexp](https://github.com/jerily/tpathexp) package (1.1.0 or later).
The server handles connections, HTTP parsing, TLS, and response writes.
Create one router per worker interpreter during initialization and reuse it
across requests.

twebserver supplies two native C integration commands:
`::twebserver::process_conn` translates `httpMethod` to `method`, dispatches the
request, and sends the response with `::twebserver::return_response`. It logs
unexpected errors and sends a 500 response. `::twebserver::invoke_handler`
composes middleware and guards around existing `{ctx req}` handlers.

Load both packages in each worker and call the native commands directly. A
single alias binds the worker's router to the server callback:

```tcl
package require twebserver 2.0.0
set init_script {
    package require twebserver 2.0.0
    package require tpathexp 1.1.0

    proc get_user {ctx req} {
        set id [::twebserver::get_path_param $req id]
        return [::twebserver::build_response 200 text/plain "User $id"]
    }

    set router [::tpathexp::router]
    $router add GET /users/:id \
        [list ::twebserver::invoke_handler ::get_user {} {}] -strict true
    interp alias {} process_conn {} ::twebserver::process_conn $router
}
set server [::twebserver::create_server {} process_conn $init_script]
::twebserver::listen_server -http $server 8080
::twebserver::wait_signal
::twebserver::destroy_server $server
```

`invoke_handler` takes a handler command prefix, a middleware list, and a guard
list before the `request context params` arguments supplied by tpathexp. Empty
lists disable middleware and guards. Existing application handlers can retain
their `{ctx req}` signature and use `get_path_param`, `get_form`, `build_response`,
and `build_response -return_file` normally. See [Middleware](middleware.md) for
composition examples.

Handlers written directly for tpathexp accept `{req ctx params}` and can be
registered without `invoke_handler`. They return response dictionaries with
`statusCode` and `body`; optional headers and other fields are preserved.

## Routes and matching

```tcl
$router add GET /users/:id ::get_user -strict true
$router add {POST PUT} /users/:id ::save_user
$router add GET {/users/:id([0-9]+)} ::get_numeric_user
$router add GET {/:path(.*)} ::not_found
```

The handlers in this snippet use tpathexp's `{req ctx params}` signature.
Register specific routes before a catch-all. Bare `*` is unsupported; use
`/:path(.*)` for a catch-all, including the root path. Options take explicit
boolean values: `-strict true` rejects an extra trailing slash, and
`-nocase true` enables case-insensitive matching. Custom patterns use POSIX
extended regular expressions. Use Tcl braces around patterns containing brackets.

GET routes also accept HEAD; dispatch clears response bodies for HEAD requests.
No matching path produces 404. A matching path with no matching method produces
405 with an `Allow` header. A GET catch-all matches every path for method checking,
so other methods can receive 405 even for an otherwise unknown URL. Matching
GET catch-alls still return the application's custom 404 response. OPTIONS has
no automatic handling.

Paths and captures are used as supplied; tpathexp does not URL-decode or normalize
them. The `path` field from twebserver already separates the query string.

## Migrating from 1.x

The old bundled router implementation has been removed, but
`::twebserver::create_router`, `add_route`, `info_routes`, `add_middleware`, and `create_server -with_router`
remain as **deprecated compatibility APIs**. The Tcl shim uses tpathexp and the
same native middleware and connection helpers as the examples. It preserves
`{ctx req}` handlers, middleware and guard signatures, route names (`ctx route_name`), traced-variable lifetime,
and registration order. The `-with_router` flag is accepted but no longer
selects a special C dispatch path. There is no `-router` option.

```tcl
# Existing initialization scripts can still use this form:
::twebserver::create_router -command_name process_conn router
::twebserver::add_route -strict $router GET /users/:id get_user
# ...then create_server -with_router $config process_conn $init_script
```

The shim translates bare `*` to a named catch-all internally and hides that
synthetic capture from legacy handlers. Literal routes retain 1.x exact-path
matching. Parameterized/custom patterns now use tpathexp's POSIX regex engine;
Tcl-specific regex constructs need migration. Dispatch uses the tpathexp
HEAD/405 behavior described above, so API compatibility does not imply identical
HTTP method behavior to 1.x. Use `package require twebserver 2.0.0` when updating
an application that explicitly required the 1.x package series.

For new code, use `tpathexp::router`, `$router add`, and the normal server callback
interface. An old `-prefix` route can be expressed with `-end false`. This performs
raw prefix matching: `/api` also matches `/apix`. For a segment boundary, register
`/api` and `/api/:path(.*)` separately. Routers belong to their creating interpreter;
do not share a router command between worker threads. Their tables are released
when the worker interpreter is deleted.
