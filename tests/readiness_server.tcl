# Server fixture for readiness_test.tcl.
# Ports and package location come from the runner.
lassign $argv libdir http_port tls_port
lappend auto_path $libdir
package require twebserver

set init_script [list lappend auto_path $libdir]
append init_script {
    package require twebserver

    proc process_conn {ctx req} {
        switch -- [dict get $req path] {
            /large { set body [string repeat x [expr {8 * 1024 * 1024}]] }
            /chunked { set body [string repeat x [expr {12 * 1024 * 1024}]] }
            /echo { set body [dict get $req body] }
            /echo-binary {
                ::twebserver::return_response [dict get $ctx conn] \
                    [dict create statusCode 200 body [dict get $req body] \
                        isBase64Encoded [dict get $req isBase64Encoded]]
                return
            }
            /head-length {
                ::twebserver::return_response [dict get $ctx conn] \
                    [dict create statusCode 200 body {} headers {content-length 12345678901}]
                return
            }
            /head-multi {
                ::twebserver::return_response [dict get $ctx conn] \
                    [dict create statusCode 200 body {} headers {Content-Length 17} \
                        multiValueHeaders {Content-Length {42}}]
                return
            }
            /binary {
                ::twebserver::return_response [dict get $ctx conn] \
                    [dict create statusCode 200 body AAEC/w== isBase64Encoded 1]
                return
            }
            /framing {
                ::twebserver::return_response [dict get $ctx conn] \
                    [dict create statusCode 200 body ok headers {Content-Length 999 Transfer-Encoding chunked}]
                return
            }
            /cookies {
                ::twebserver::return_response [dict get $ctx conn] \
                    [dict create statusCode 200 body ok multiValueHeaders \
                        [dict create Set-Cookie [list {a=1; Path=/} {b=2; Expires=Wed, 21 Oct 2037 07:28:00 GMT}]]]
                return
            }
            /deferred {
                after 0 [list ::twebserver::return_response [dict get $ctx conn] \
                    [dict create statusCode 200 body ok]]
                return
            }
            /nested {
                after 2500 { set ::handler_done 1 }
                vwait ::handler_done
                set body late
            }
            default { set body ok }
        }
        ::twebserver::return_response [dict get $ctx conn] \
            [::twebserver::build_response 200 text/plain $body] utf-8
    }
}

set config [dict create read_timeout_millis 1500 conn_timeout_millis 2000 \
    num_threads 1 garbage_collection_cleanup_threshold 3 gzip on gzip_types {text/plain} gzip_min_length 8192]
set server [::twebserver::create_server $config process_conn $init_script]
set certdir [file normalize [file join [file dirname [info script]] ../certs/host1]]
::twebserver::add_context $server localhost \
    [file join $certdir key.pem] [file join $certdir cert.pem]
::twebserver::listen_server -http -host 127.0.0.1 -num_threads 1 $server $http_port
::twebserver::listen_server -host 127.0.0.1 -num_threads 1 $server $tls_port

# Let the runner stop the process through stdin and exercise normal destruction.
fconfigure stdin -blocking 0
fileevent stdin readable {
    if {[gets stdin line] >= 0 || [eof stdin]} { set ::done 1 }
}
puts READY
flush stdout
vwait ::done
::twebserver::destroy_server $server
