# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

package require twebserver 2.0.0

set init_script {
    package require twebserver 2.0.0
    package require tpathexp 1.1.0

    namespace eval simple_session_manager {
        proc enter {ctx req} {
            dict set req session [dict create id 1234567890]
            return $req
        }
        proc leave {ctx req res} {
            set res [::twebserver::add_cookie -maxage 3600 $res session_id [dict get $req session id]]
            return $res
        }
    }

    set router [::tpathexp::router]
    set middleware {{::simple_session_manager::enter ::simple_session_manager::leave}}
    foreach {method path handler} {
        GET  /                    ::get_index_page_handler
        GET  /blog/:user_id/sayhi  ::get_blog_entry_handler
        GET  /addr                ::get_addr_handler
        POST /example             ::post_example_handler
        GET  /logo                ::get_logo_handler
    } {
        $router add $method $path \
            [list ::twebserver::invoke_handler $handler $middleware {}] -strict true
    }
    $router add GET {/:path(.*)} \
        [list ::twebserver::invoke_handler ::get_catchall_handler $middleware {}]

    interp alias {} process_conn {} ::twebserver::process_conn $router

    proc get_index_page_handler {ctx req} {
        set html {
            <html>
                <body>
                    <img src=/logo />
                    <h1>hello world</h1>
                    <ul>
                        <li><a href=/blog/123/sayhi>click here to see how path parameters work</a></li>
                        <li><a href=/addr>click here to see your IP address</a></li>
                        <li><form method=post enctype="multipart/form-data" action=/example><input type=text name=field1><input type=file name=field2><input type=submit></form></li>
                    </ul>
                </body>
            </html>
        }
        set res [::twebserver::build_response 200 text/html $html]
        return $res
    }

    proc get_logo_handler {ctx req} {
        set dir [::twebserver::get_rootdir]
        set filepath [file join $dir plume.png]
        set res [::twebserver::build_response -return_file 200 image/png $filepath]
        return $res
    }

    proc get_catchall_handler {ctx req} {
        set res [::twebserver::build_response 404 text/plain "not found"]
        return $res
    }

    proc post_example_handler {ctx req} {
        set form [::twebserver::get_form $req]
        #puts form=$form

        # build the response dictionary
        set res [::twebserver::build_response 200 text/plain \
            "test message POST addr=[dict get $ctx addr] headers=[dict get $req headers] fields=[dict get $form fields]"]

        return $res
    }

    proc get_blog_entry_handler {ctx req} {

        # get IP address of client from the context dictionary
        set addr [dict get $ctx addr]

        # get a boolean value from the context dictionary that indicates if the connection is secure
        # it should be true when you make HTTPS requests to the server, false for HTTP requests
        set isSecureProto [dict get $ctx isSecureProto]

        # get a path parameter from the request dictionary
        set user_id [::twebserver::get_path_param $req user_id]

        # build the response dictionary
        set res [::twebserver::build_response 200 text/plain \
            "test message GET user_id=$user_id addr=$addr isSecureProto=$isSecureProto"]
        return $res
    }

    proc get_addr_handler {ctx req} {
        set ipv6_addr [dict get $ctx addr]
        set ipv4_addr [::twebserver::ipv6_to_ipv4 $ipv6_addr]
        set res [::twebserver::build_response 200 text/plain "addr=$ipv6_addr addr_ipv4=$ipv4_addr"]
        return $res
    }

}

# use threads and gzip compression
set config_dict [dict create \
    rootdir [file dirname [info script]] \
    gzip on \
    gzip_types [list text/html text/plain application/json] \
    gzip_min_length 8192]

# create the server
set server_handle [::twebserver::create_server $config_dict process_conn $init_script]

# add SSL context to the server
set dir [file dirname [info script]]
::twebserver::add_context $server_handle localhost [file join $dir "../certs/key.pem"] [file join $dir "../certs/cert.pem"]

# listen for an HTTPS connection on port 4433
::twebserver::listen_server -num_threads 8 $server_handle 4433

# listen for an HTTP connection on port 8080
::twebserver::listen_server -http -num_threads 4 $server_handle 8080

# print that the server is running
puts "server is running. go to https://localhost:4433/ or http://localhost:8080/"

# wait forever
::twebserver::wait_signal
#vwait forever

# destroy the server
::twebserver::destroy_server $server_handle

