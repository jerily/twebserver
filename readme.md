# twebserver

TCL Web Server (HTTPS) Extension

## Modules and Extensions

* [tjson](https://github.com/jerily/tjson) - parse and serialize json in TCL
* [tink-tcl](https://github.com/jerily/tink-tcl) - cryptographic APIs that are secure, easy to use correctly, and hard(er) to misuse.
* [aws-sdk-tcl](https://github.com/jerily/aws-sdk-tcl) - use AWS services with TCL (S3, DynamoDB, Lambda, SQS and some IAM and SSM support)
* [ksuid-tcl](https://github.com/jerily/ksuid-tcl) - K-Sortable Unique Identifiers (KSUIDs) in TCL
* [snappy-tcl](https://github.com/jerily/snappy-tcl) - TCL bindings for a fast compressor / decompressor library by google
* [bcrypt-tcl](https://github.com/jerily/bcrypt-tcl) - TCL module for bcrypt, a password-hashing function.
* [tmfa](https://github.com/jerily/tmfa) - Multi-Factor Authentication (MFA) using TOTP and HOTP (see sample-2fa )
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

### Try it out without threads

Run the example:
```bash
tclsh8.6 ../examples/example-with-req-resp.tcl
```

Try a few requests:
```bash
# simple get request
curl -k https://localhost:4433
# json post request
curl -k -X POST -H "Content-Type: application/json" --data '{"message": "hello world"}' https://localhost:4433
# isBase64Encoded
curl -k -X POST -H 'content-type: image/jpeg' --data-binary @../examples/Google_2015_logo.png https://localhost:4433
# multivalue headers
curl -k -X POST -H "Content-Type: application/json" -H "X-Custom-Header: asdf" -H "X-Custom-Header: qwerty" --data '{"message": "hello world"}' https://localhost:4433
# query string parameters
curl -k -X POST -H "Content-Type: application/json" -H "X-Custom-Header: this is a test" -H "X-Custom-Header: hello world" --data '{"message": "hello world"}' 'https://localhost:4433/example?a=1&b=2&c=this+is+a+test'
# multivalue query string parameters
curl -k -X POST -H "Content-Type: application/json" -H "X-Custom-Header: this is a test" -H "X-Custom-Header: hello world" --data '{"message": "hello world"}' 'https://localhost:4433/exampl
e?a=1&b=2&c=this+is+a+test&c=blah+blah'
```

### Try it out with threads

Run the example:
```bash
tclsh8.6 ../examples/example-best-with-native-threads.tcl
```

## Benchmark

Install go and gohttpbench:
```
brew install go
go install github.com/parkghost/gohttpbench@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

With keepalive (example-best-with-native-threads.tcl - uses parse_conn/return_conn): 
```
gohttpbench -v 10 -n 100000 -c 10 -t 10 -k "https://localhost:4433/example?a=1&b=2"

Concurrency Level:      10
Time taken for tests:   1.51 seconds
Complete requests:      100000
Failed requests:        0
HTML transferred:       23700000 bytes
Requests per second:    66290.23 [#/sec] (mean)
Time per request:       0.151 [ms] (mean)
Time per request:       0.015 [ms] (mean, across all concurrent requests)
HTML Transfer rate:     15342.21 [Kbytes/sec] received
```

Without keepalive (example-best-with-native-threads.tcl - uses parse_conn/return_conn):
```
gohttpbench -v 10 -n 100000 -c 10 -t 10 "https://localhost:4433/example?a=1&b=2"

Concurrency Level:      10
Time taken for tests:   10.00 seconds
Complete requests:      35832
Failed requests:        0
HTML transferred:       8313024 bytes
Requests per second:    3583.20 [#/sec] (mean)
Time per request:       2.791 [ms] (mean)
Time per request:       0.279 [ms] (mean, across all concurrent requests)
HTML Transfer rate:     811.80 [Kbytes/sec] received
```
