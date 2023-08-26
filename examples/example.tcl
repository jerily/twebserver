lappend auto_path [file join [file dirname [info script]] ..]
package require tws
package require Thread

set thread_script {
    lappend auto_path [file join [file dirname [info script]] ..]
    package require tws

    proc thread_process_request {requestVar} {
        upvar $requestVar request
        set request_dict [::tws::parse_request $request]
        return "HTTP/1.1 200 OK\n\ntest message request_dict=$request_dict\n"
    }

    proc thread_process_conn {conn addr port} {
        puts "thread_process_conn $conn $addr $port"
        if { [catch {
            set request [::tws::read_conn $conn]
            set reply [thread_process_request request]
            ::tws::write_conn $conn $reply
        } errmsg] } {
            puts "error: $errmsg"
        }
        ::tws::close_conn $conn
        puts done
    }

}

set pool [tpool::create -minworkers 5 -maxworkers 20 -idletime 40 -initcmd $thread_script]

proc process_conn {conn addr port} {
    puts "processing connection... $conn $addr $port"
    global pool
    ::tpool::post -detached -nowait $pool [list thread_process_conn $conn $addr $port]
}

set config_dict [dict create key "../certs/key.pem" cert "../certs/cert.pem"]
set server_handle [::tws::create_server $config_dict process_conn]
::tws::listen_server $server_handle 4433
::tws::destroy_server $server_handle

