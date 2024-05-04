# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

package require twebserver

set init_script {
    package require twebserver

    proc process_conn {conn client_ip port} {
        set conn_info [::twebserver::info_conn $conn]
        set req [dict get $conn_info request]
        set http_method [dict get $req httpMethod]
        set path [dict get $req path]
        set query [dict get $req queryString]
        set query_dict {}
        if { $query ne {} } {
            set query_dict [::twebserver::parse_query $query]
        }

        ::twebserver::return_response $conn [::twebserver::build_response 200 \
            "text/plain" "Hello, world! client_ip=$client_ip httpMethod=$http_method port=$port path=$path query_dict=$query_dict\n"]
    }

}

# use threads and gzip compression
set config_dict [dict create rootdir [file dirname [info script]]]

# create the server
set server_handle [::twebserver::create_server $config_dict process_conn $init_script]

# add SSL context to the server
set dir [file dirname [info script]]
::twebserver::add_context $server_handle localhost [file join $dir "../certs/host1/key.pem"] [file join $dir "../certs/host1/cert.pem"]
::twebserver::add_context $server_handle www.example.com [file join $dir "../certs/host2/key.pem"] [file join $dir "../certs/host2/cert.pem"]

# listen for an HTTPS connection on port 4433
::twebserver::listen_server -num_threads 8 $server_handle 4433

# listen for an HTTP connection on port 8080
::twebserver::listen_server -http -num_threads 4 $server_handle 8080

# print that the server is running
puts "server is running. go to https://localhost:4433/ or http://localhost:8080/"

# wait forever
::twebserver::wait
#vwait forever

# destroy the server
::twebserver::destroy_server $server_handle

