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

## Examples

* [Threads & Routing & Middleware example](examples/example-best-with-router.tcl)

## Benchmark

Start the server:
```
tclsh9.0 examples/example-best-with-router.tcl
```

Install go and gohttpbench:
```
# linux: apt install golang-go
# macOS: brew install go
go install github.com/parkghost/gohttpbench@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

HTTPS (8 threads) - With keepalive - Linux - Intel i9 CPU @ 3.60GHz with 64GB RAM: 
```
gohttpbench -v 10 -n 100000 -c 10 -t 1000 -k "https://localhost:4433/blog/12345/sayhi"

Concurrency Level:      10
Time taken for tests:   1.29 seconds
Complete requests:      100000
Failed requests:        0
HTML transferred:       6800000 bytes
Requests per second:    77313.19 [#/sec] (mean)
Time per request:       0.129 [ms] (mean)
Time per request:       0.013 [ms] (mean, across all concurrent requests)
HTML Transfer rate:     5133.60 [Kbytes/sec] received
```

HTTPS (8 threads) - Without keepalive - Linux - Intel i9 CPU @ 3.60GHz with 64GB RAM:
```
gohttpbench -v 10 -n 100000 -c 10 -t 1000 "https://localhost:4433/blog/12345/sayhi"

Concurrency Level:      10
Time taken for tests:   23.16 seconds
Complete requests:      100000
Failed requests:        0
HTML transferred:       6800000 bytes
Requests per second:    4318.27 [#/sec] (mean)
Time per request:       2.316 [ms] (mean)
Time per request:       0.232 [ms] (mean, across all concurrent requests)
HTML Transfer rate:     286.73 [Kbytes/sec] received
```

HTTP (4 threads) - With keepalive - Linux - Intel i9 CPU @ 3.60GHz with 64GB RAM:
```
gohttpbench -v 10 -n 100000 -c 10 -t 1000 -k "http://localhost:8080/blog/12345/sayhi"

Concurrency Level:      10
Time taken for tests:   1.19 seconds
Complete requests:      100000
Failed requests:        0
HTML transferred:       6800000 bytes
Requests per second:    84002.01 [#/sec] (mean)
Time per request:       0.119 [ms] (mean)
Time per request:       0.012 [ms] (mean, across all concurrent requests)
HTML Transfer rate:     5577.73 [Kbytes/sec] received
```

HTTP (4 threads) - Without keepalive - Linux - Intel i9 CPU @ 3.60GHz with 64GB RAM:
```
gohttpbench -v 10 -n 100000 -c 10 -t 1000 "http://localhost:8080/blog/12345/sayhi"

Concurrency Level:      10
Time taken for tests:   2.77 seconds
Complete requests:      100000
Failed requests:        0
HTML transferred:       6800000 bytes
Requests per second:    36071.08 [#/sec] (mean)
Time per request:       0.277 [ms] (mean)
Time per request:       0.028 [ms] (mean, across all concurrent requests)
HTML Transfer rate:     2395.12 [Kbytes/sec] received
```
