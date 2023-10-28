# twebserver

TCL Web Server (HTTPS) Extension

## Features

* High performance web server (HTTPS) written in C and Tcl.
* It uses a highly efficient event-driven model with fixed number of threads to manage connections.
* It can be easily extended.
* It is a TCL loadable module.
* It supports multiple certificates for different hosts (SNI).
* Keepalive connections
* Compression (gzip)


## Modules and Extensions

* [tjson](https://github.com/jerily/tjson) - parse and serialize json in TCL
* [tink-tcl](https://github.com/jerily/tink-tcl) - cryptographic APIs that are secure, easy to use correctly, and hard(er) to misuse.
* [aws-sdk-tcl](https://github.com/jerily/aws-sdk-tcl) - use AWS services with TCL (S3, DynamoDB, Lambda, SQS and some IAM and SSM support)
* [ksuid-tcl](https://github.com/jerily/ksuid-tcl) - K-Sortable Unique Identifiers (KSUIDs) in TCL
* [snappy-tcl](https://github.com/jerily/snappy-tcl) - TCL bindings for a fast compressor / decompressor library by google
* [bcrypt-tcl](https://github.com/jerily/bcrypt-tcl) - TCL module for bcrypt, a password-hashing function.
* [tmfa](https://github.com/jerily/tmfa) - Multi-Factor Authentication (MFA) using TOTP and HOTP
* [tqrcodegen](https://github.com/jerily/tqrcodegen) - generate QR codes as SVG images
* [tdom](http://www.tdom.org/) - XML parser and more 

## Getting Started

* [Installation Guide](docs/install.md)
* [Generating Certificates](docs/certs.md)
* [TCL Commands](docs/commands.md)
* [Server Configuration](docs/config.md)
* [Routing](docs/routing.md)
* [Middleware](docs/middleware.md)

## Examples

* [Threads & Routing & Middleware example](examples/example-best-with-router.tcl)

## Benchmark

Start the server:
```
tclsh8.6 examples/example-best-with-router.tcl
```

Install go and gohttpbench:
```
brew install go
go install github.com/parkghost/gohttpbench@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

With keepalive - Intel i9 CPU @ 3.60GHz with 64GB RAM: 
```
gohttpbench -v 10 -n 100000 -c 10 -t 1000 -k "https://localhost:4433/blog/12345/sayhi"

Concurrency Level:      10
Time taken for tests:   1.17 seconds
Complete requests:      100000
Failed requests:        0
HTML transferred:       5200000 bytes
Requests per second:    85497.45 [#/sec] (mean)
Time per request:       0.117 [ms] (mean)
Time per request:       0.012 [ms] (mean, across all concurrent requests)
HTML Transfer rate:     4341.56 [Kbytes/sec] received
```

Without keepalive - Intel i9 CPU @ 3.60GHz with 64GB RAM:
```
gohttpbench -v 10 -n 100000 -c 10 -t 1000 "https://localhost:4433/blog/12345/sayhi"

Concurrency Level:      10
Time taken for tests:   23.95 seconds
Complete requests:      100000
Failed requests:        0
HTML transferred:       5200000 bytes
Requests per second:    4175.56 [#/sec] (mean)
Time per request:       2.395 [ms] (mean)
Time per request:       0.239 [ms] (mean, across all concurrent requests)
HTML Transfer rate:     212.04 [Kbytes/sec] received
```
