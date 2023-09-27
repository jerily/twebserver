# Configuration Parameters for twebserver

* **max_request_read_bytes** - the maximum number of bytes to read from a request (Default: 10485760)
* **max_read_buffer_size** - the maximum size of the read buffer (Default: 1048576)
* **backlog** - the maximum number of connections to queue (Default: SOMAXCONN)
* **conn_timeout_millis** - the timeout for a connection in milliseconds (Default: 900000)
* **garbage_collection_interval_millis** - the interval for garbage collection in milliseconds (Default: 60000)
* **keepalive** - whether keepalive is on or off (Default: 1)
* **keepidle** - the time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes (Default: 10)
* **keepintvl** - the time (in seconds) between individual keepalive probes (Default: 5)
* **keepcnt** - The maximum number of keepalive probes TCP should send before dropping the connection (Default: 3)
* **num_threads** - the number of threads to use (Default: 10)
* **thread_stacksize** - the stack size for each thread in bytes (Default: 0) 0 means use the default OS thread stack size
* **thread_max_concurrent_conns** - the maximum number of concurrent connections per thread (Default: 0)
This is set to preserve memory usage.
If you have a lot of concurrent keepalive connections,
you may want to set this to a low number. Default is 0, which means unlimited.
* **gzip** - whether gzip is on or off (Default: 1)
* **gzip_min_length** - the minimum length of a response to gzip (Default: 8192)
* **gzip_types** - compresses responses only with MIME type text/html, to compress responses with other MIME types, list the additional types of content to gzip (Default: text/html)