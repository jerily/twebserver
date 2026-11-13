# twebserver

TCL Web Server Extension

## Features

* High performance web server (HTTP & HTTPS) written in C and Tcl.
* It uses a highly efficient event-driven model with fixed number of threads to manage connections.
* It can be easily extended.
* It is a TCL loadable module.
* It supports multiple certificates for different hosts (SNI).
* Keepalive connections
* Compression (gzip)
* Routing via the optional [tpathexp](https://github.com/jerily/tpathexp) package
* Client Certificate Verification


## Version 2.0.0

The bundled path matcher and native router implementation have been removed.
The old router commands and `-with_router` option remain as deprecated
compatibility APIs backed by tpathexp. New applications use the ordinary
`create_server config callback init_script` interface and send responses with
`return_response`. Routing examples use tpathexp 1.1.0 or later
and native C commands in twebserver for middleware, guards, and connection
adaptation. Each worker loads both packages and binds its router with one alias
to `::twebserver::process_conn`. See [Routing](docs/routing.md) for migration
details. tpathexp is an example/test dependency, not a linked dependency of the
server extension. The compatibility router also loads it on demand.

## Modules and Extensions

* [jinja2-tcl](https://github.com/jerily/jinja2-tcl) - Jinja2 template engine for Tcl.
* [tjson](https://github.com/jerily/tjson) - parse and serialize json in TCL
* [valkey-tcl](https://github.com/jerily/valkey-tcl) - interface to the Valkey (redis) store.
* [tink-tcl](https://github.com/jerily/tink-tcl) - cryptographic APIs that are secure, easy to use correctly, and hard(er) to misuse.
* [aws-sdk-tcl](https://github.com/jerily/aws-sdk-tcl) - use AWS services with TCL (S3, DynamoDB, Lambda, SQS and some IAM and SSM support)
* [ksuid-tcl](https://github.com/jerily/ksuid-tcl) - K-Sortable Unique Identifiers (KSUIDs) in TCL
* [snappy-tcl](https://github.com/jerily/snappy-tcl) - TCL bindings for a fast compressor / decompressor library by google
* [bcrypt-tcl](https://github.com/jerily/bcrypt-tcl) - TCL module for bcrypt, a password-hashing function.
* [tmfa](https://github.com/jerily/tmfa) - Multi-Factor Authentication (MFA) using TOTP and HOTP
* [tqrcodegen](https://github.com/jerily/tqrcodegen) - generate QR codes as SVG images
* [tdom](http://www.tdom.org/) - XML parser and more 

## Middleware

* [tsession](https://github.com/jerily/tsession) - Simple Session Management
* [tratelimit](https://github.com/jerily/tratelimit) - Rate Limiting Middleware
* [treqmon](https://github.com/jerily/treqmon) - Request Monitoring and Logger Middleware

## Getting Started

* [Installation Guide](docs/install.md)
* [Generating Certificates](docs/certs.md)
* [TCL Commands](docs/commands.md)
* [Server Configuration](docs/config.md)
* [Routing](docs/routing.md)
* [Middleware](docs/middleware.md)
* [Context, Request, and Response Dictionaries](docs/ctx_req_res_dict.md)
* [Benchmarking](docs/benchmark.md)

## Examples

HEAD responses send headers without a body. By default, `Content-Length` is
computed from the response body, including base64 decoding and gzip. A HEAD
handler may instead supply a nonnegative `Content-Length` header and an empty
body. The server owns response framing and emits each framing header once.
Values in `multiValueHeaders` are emitted as separate header fields, including `Set-Cookie`.

* [Threads, tpathexp routing, and middleware](examples/example-best-with-router.tcl)
* [SQLite with tpathexp](examples/example-with-sqlite.tcl)
* [Server without routing](examples/example-without-routing.tcl)
