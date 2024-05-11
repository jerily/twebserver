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
* Routing & Middleware functionality
* Client Certificate Verification


## Modules and Extensions

* [thtml](https://github.com/jerily/thtml) - HTML Templating Engine for TCL
* [tjson](https://github.com/jerily/tjson) - parse and serialize json in TCL
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

* [Threads & Routing & Middleware example](examples/example-best-with-router.tcl)
