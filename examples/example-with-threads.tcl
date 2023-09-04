package require twebserver
package require Thread

set thread_script {
    package require twebserver

    proc thread_process_request {request_dict} {
        return "HTTP/1.1 200 OK\n\ntest message request_dict=$request_dict\n"
    }

    proc thread_process_conn {conn addr port} {
        if { [catch {
            set reply [thread_process_request [::twebserver::parse_conn $conn]]
            ::twebserver::write_conn $conn $reply
        } errmsg] } {
            puts "error: $errmsg"
        }
        ::twebserver::close_conn $conn
    }

}

set pool [::tpool::create -minworkers 5 -maxworkers 20 -idletime 40 -initcmd $thread_script]

proc process_conn {conn addr port} {
    global pool
    ::tpool::post -detached -nowait $pool [list thread_process_conn $conn $addr $port]
}

set max_request_read_bytes [expr { 10 * 1024 * 1024 }]
set max_read_buffer_size [expr { 1024 * 1024 }]
set config_dict [dict create max_request_read_bytes $max_request_read_bytes max_read_buffer_size $max_read_buffer_size]
set server_handle [::twebserver::create_server $config_dict process_conn]
::twebserver::add_context $server_handle localhost "../certs/host1/key.pem" "../certs/host1/cert.pem"
::twebserver::add_context $server_handle www.example.com "../certs/host2/key.pem" "../certs/host2/cert.pem"
::twebserver::listen_server $server_handle 4433
vwait forever
::twebserver::destroy_server $server_handle
