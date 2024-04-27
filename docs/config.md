# Configuration Parameters for twebserver

* **max_request_read_bytes** - the maximum number of bytes to read from a request (Default: 10485760)
* **max_read_buffer_size** - the maximum size of the read buffer (Default: 32768)
* **backlog** - the maximum number of connections to queue (Default: SOMAXCONN)
* **conn_timeout_millis** - the timeout for a connection in milliseconds (Default: 900000)
* **read_timeout_millis** - the timeout for reading from a connection in milliseconds (Default: 30000)
* **garbage_collection_cleanup_threshold** - how often to attempt cleanup of timed out connections in number of requests (Default: 10000)
* **garbage_collection_interval_millis** - the interval for garbage collection in milliseconds (Default: 60000)
* **keepalive** - whether keepalive is on or off (Default: 1)
* **keepidle** - the time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes (Default: 10)
* **keepintvl** - the time (in seconds) between individual keepalive probes (Default: 5)
* **keepcnt** - The maximum number of keepalive probes TCP should send before dropping the connection (Default: 3)
* **num_threads** - the default number of threads to use per listener (Default: 10). It is overridden by the listener's num_threads parameter.
* **thread_stacksize** - the stack size for each thread in bytes (Default: 0) 0 means use the default OS thread stack size
* **thread_max_concurrent_conns** - the maximum number of concurrent connections per thread (Default: 0)
This is set to preserve memory usage.
If you have a lot of concurrent keepalive connections,
you may want to set this to a low number. Default is 0, which means unlimited.
* **gzip** - whether gzip is on or off (Default: 1)
* **gzip_min_length** - the minimum length of a response to gzip (Default: 8192)
* **gzip_types** - compresses responses only with MIME type text/html. To compress responses with other MIME types, list the additional types of content to gzip.
* **rootdir** - the root directory for serving files (Default: "")