# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

package require twebserver

set init_script {
    package require twebserver

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

    # create a router
    set router [::twebserver::create_router]

    # add middleware to the router
    ::twebserver::add_middleware \
        -enter_proc simple_session_manager::enter \
        -leave_proc simple_session_manager::leave \
        $router

    # add a route that will be called if the request method is GET and the path is "/"
    ::twebserver::add_route -strict $router GET / get_index_page_handler

    # add a route that has a path parameter called "user_id"
    # when the route path expression matches, it will call "get_blog_entry_handler" proc
    ::twebserver::add_route -strict $router GET /blog/:user_id/sayhi get_blog_entry_handler

    # add a route that will be called if the request method is GET and the path is "/addr"
    ::twebserver::add_route -strict $router GET /addr get_addr_handler

    # add a route that will be called if the request method is POST and the path is "/example"
    ::twebserver::add_route -strict $router POST /example post_example_handler

    # add a route that will be called if the request method is GET and the path is "/logo"
    ::twebserver::add_route -strict $router GET /logo get_logo_handler

    # add a catchall route that will be called if no other route matches a GET request
    ::twebserver::add_route $router GET "*" get_catchall_handler

    # make sure that the router will be called when the server receives a connection
    interp alias {} process_conn {} $router

    proc get_index_page_handler {ctx req} {
        set html {
            <html>
                <body>
                    <img src=/logo />
                    <h1>hello world</h1>
                    <ul>
                        <li><a href=/blog/123/sayhi>click here to see how path parameters work</a></li>
                        <a href=/addr>click here to see your IP address</a>
                    </ul>
                </body>
            </html>
        }
        set res [::twebserver::build_response 200 text/html $html]
        return $res
    }

    proc get_logo_handler {ctx req} {
        set server_handle [dict get $ctx server]
        set dir [::twebserver::get_rootdir $server_handle]
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

        # get the JA3 fingerprint of the client
        set ja3_fingerprint [dict get $ctx ja3_fingerprint]

        # get a path parameter from the request dictionary
        set user_id [::twebserver::get_path_param $req user_id]

        # build the response dictionary
        set res [::twebserver::build_response 200 text/plain \
            "test message GET user_id=$user_id addr=$addr isSecureProto=$isSecureProto ja3_fingerprint=$ja3_fingerprint"]
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
    num_threads 10 \
    rootdir [file dirname [info script]] \
    gzip on \
    gzip_types [list text/plain application/json] \
    gzip_min_length 20]

# create the server
set server_handle [::twebserver::create_server $config_dict process_conn $init_script]

# add SSL context to the server
::twebserver::add_context $server_handle localhost "../certs/host1/key.pem" "../certs/host1/cert.pem"
::twebserver::add_context $server_handle www.example.com "../certs/host2/key.pem" "../certs/host2/cert.pem"

# listen for an HTTPS connection on port 4433
::twebserver::listen_server $server_handle 4433

# listen for an HTTP connection on port 8080
::twebserver::listen_server -http $server_handle 8080

# print that the server is running
puts "server is running. go to https://localhost:4433/ or http://localhost:8080/"

# wait forever
vwait forever

# destroy the server
::twebserver::destroy_server $server_handle

