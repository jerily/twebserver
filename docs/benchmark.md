## Benchmark

Start the server:
```
tclsh9.0 examples/example-best-with-router.tcl
```

### gohttpbench

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

Other things to try out:
```bash
gohttpbench -p examples/plume.png -T image/png -v 10 -n 100000 -c 10 -t 1000 "https://localhost:4433/example"
gohttpbench -p examples/plume.png -T image/png -v 10 -n 100000 -c 10 -t 1000 -k "https://localhost:4433/example"
gohttpbench -p examples/plume.png -T image/png -v 10 -n 100000 -c 10 -t 1000 "http://localhost:8080/example"
gohttpbench -p examples/plume.png -T image/png -v 10 -n 100000 -c 10 -t 1000 -k "http://localhost:8080/example"
```

### autocannon
```bash
npm install -g autocannon
npx autocannon http://localhost:8080/blog/12345/sayhi
npx autocannon https://localhost:4433/blog/12345/sayhi
```