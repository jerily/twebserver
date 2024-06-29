# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

package require twebserver

set init_script {
    package require twebserver
    package require sqlite3

    sqlite3 db1 /tmp/test.db -create true

    db1 eval {
        CREATE TABLE IF NOT EXISTS test_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT,
            last_name TEXT
        );
    }

    # create a router
    ::twebserver::create_router router

    ::twebserver::add_route -strict $router GET / get_index_page_handler
    ::twebserver::add_route -strict $router POST /add-row add_row_handler
    ::twebserver::add_route $router GET "*" get_catchall_handler

    # make sure that the router will be called when the server receives a connection
    interp alias {} process_conn {} $router

    proc get_index_page_handler {ctx req} {
        set rows_html ""
        set rows [db1 eval {SELECT * FROM test_table}]
        foreach {id first_name last_name} $rows {
            append rows_html "<li>$id: $first_name $last_name</li>"
        }
        set html [subst -nocommands -nobackslashes {
            <html>
                <body>
                    <h2>Test Table Rows</h2>
                    <ul>${rows_html}</ul>
                    <form method=post action=add-row>
                    <h2>Add a Row</h2>
                    <ul>
                        <li>First Name: <input type=text name=first_name /></li>
                        <li>Last Name: <input type=text name=last_name /></li>
                        <li><input type=submit></li>
                    </ul>
                    </form>
                </body>
            </html>
        }]
        set res [::twebserver::build_response 200 text/html $html]
        return $res
    }

    proc add_row_handler {ctx req} {
        set form [::twebserver::get_form $req]
        set first_name [dict get $form fields first_name]
        set last_name [dict get $form fields last_name]
        db1 eval {INSERT INTO test_table (first_name, last_name) VALUES ($first_name, $last_name)}
        return [::twebserver::build_redirect 302 "/"]
    }

    proc get_catchall_handler {ctx req} {
        set res [::twebserver::build_response 404 text/plain "not found"]
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
set server_handle [::twebserver::create_server -with_router $config_dict process_conn $init_script]

# add SSL context to the server
set dir [file dirname [info script]]

set localhost_key [file join $dir "../certs/host1/key.pem"]
set localhost_cert [file join $dir "../certs/host1/cert.pem"]
::twebserver::add_context $server_handle localhost $localhost_key $localhost_cert

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

