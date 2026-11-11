#!/usr/bin/env tclsh
# Socket readiness and HTTP framing regressions. Requires Tcl, tcltest and openssl.
# Run: tclsh9.1 tests/readiness_test.tcl --libdir build
# Select tests with tcltest options, e.g. -match readiness-fragmented-*.
# CPU assertions use Linux /proc; functional assertions run on other Unix hosts.
# Core Tcl cannot explicitly set SO_LINGER/SO_RCVBUF;
# closing an unread response exercises disconnect cleanup without those options.

namespace eval ::readiness {
    variable here [file dirname [file normalize [info script]]]
    variable libdir [file join [file dirname $here] build]
    variable tclsh [info nameofexecutable]
    variable clients {}
    variable childPids {}
    variable pending {}
    variable server {}
    variable serverPid {}
    variable logPath {}
    variable ticks 0
    variable wake
}

set testArgs {}
for {set i 0} {$i < [llength $argv]} {incr i} {
    set arg [lindex $argv $i]
    switch -- $arg {
        --libdir - --tclsh {
            if {[incr i] >= [llength $argv]} { error "missing value for $arg" }
            set ::readiness::[string range $arg 2 end] [lindex $argv $i]
        }
        --help {
            puts "Usage: [info nameofexecutable] $argv0 ?--libdir build? ?--tclsh path? ?tcltest options?"
            exit 0
        }
        default { lappend testArgs $arg }
    }
}
set argv {}
package require tcltest 2
::tcltest::configure {*}$testArgs
set ::readiness::libdir [file normalize $::readiness::libdir]
set ::readiness::openssl [auto_execok openssl]
if {$::readiness::openssl eq {}} { error "openssl is required for the TLS client tests" }
if {[file exists /proc/self/stat] && ![catch {exec getconf CLK_TCK} ticks]} {
    set ::readiness::ticks $ticks
} else {
    puts "CPU assertions unavailable; running functional checks."
}
source [file join $::readiness::here readiness_tls_proxy.tcl]

proc ::readiness::check {condition message} {
    if {![uplevel 1 [list expr $condition]]} { error $message }
}

proc ::readiness::waitFor {channel event deadline} {
    variable wake
    set remaining [expr {$deadline - [clock clicks -milliseconds]}]
    if {$remaining <= 0} { error "timed out waiting for $event on $channel" }
    set wake {}
    set timer [after $remaining [list set ::readiness::wake timeout]]
    fileevent $channel $event [list set ::readiness::wake ready]
    try {
        vwait ::readiness::wake
        if {$wake eq "timeout"} { error "timed out waiting for $event on $channel" }
    } finally {
        after cancel $timer
        fileevent $channel $event {}
    }
}

proc ::readiness::chunk {channel deadline} {
    while {1} {
        set data [read $channel 65536]
        if {$data ne {} || [eof $channel]} { return $data }
        waitFor $channel readable $deadline
    }
}

proc ::readiness::binaryChannel {channel} {
    fconfigure $channel -translation binary -blocking 0 -buffering none
    return $channel
}

proc ::readiness::reservePorts {} {
    set first [socket -server {apply {{ch args} {close $ch}}} -myaddr 127.0.0.1 0]
    try {
        set second [socket -server {apply {{ch args} {close $ch}}} -myaddr 127.0.0.1 0]
        try {
            return [list [lindex [fconfigure $first -sockname] end] \
                         [lindex [fconfigure $second -sockname] end]]
        } finally { close $second }
    } finally { close $first }
}

proc ::readiness::log {} {
    variable logPath
    if {$logPath eq {}} { return {} }
    set ch [open $logPath r]
    try { return [string range [read $ch] end-7999 end] } finally { close $ch }
}

proc ::readiness::start {} {
    variable clients {}
    variable childPids {}
    variable pending {}
    variable server {}
    variable serverPid {}
    variable logPath
    variable httpPort
    variable tlsPort
    variable here
    variable libdir
    variable tclsh
    lassign [reservePorts] httpPort tlsPort
    set logChannel [file tempfile logPath]
    close $logChannel
    set command [list $tclsh [file join $here readiness_server.tcl] $libdir $httpPort $tlsPort]
    set server [open [concat | $command [list 2> $logPath]] r+]
    set serverPid [lindex [pid $server] 0]
    binaryChannel $server
    set deadline [expr {[clock clicks -milliseconds] + 5000}]
    set greeting {}
    while {[string first \n $greeting] < 0} {
        append greeting [chunk $server $deadline]
        if {[eof $server]} { error "server exited during startup:\n[log]" }
    }
    check {[string trim $greeting] eq "READY"} "unexpected server greeting: $greeting\n[log]"
}

proc ::readiness::closeClient {channel} {
    variable clients
    variable childPids
    variable pending
    if {[dict exists $childPids $channel]} {
        foreach child [dict get $childPids $channel] { catch {exec kill -KILL -- $child} }
        dict unset childPids $channel
        catch {fconfigure $channel -blocking 1}
    }
    catch {close $channel}
    set index [lsearch -exact $clients $channel]
    if {$index >= 0} { set clients [lreplace $clients $index $index] }
    dict unset pending $channel
    return
}

proc ::readiness::stop {} {
    variable clients
    variable server
    variable serverPid
    variable logPath
    foreach channel $clients { closeClient $channel }
    ::readiness::proxy::stop
    try {
        if {$server ne {}} {
            try {
                puts $server "stop"
                flush $server
                set deadline [expr {[clock clicks -milliseconds] + 5000}]
                while {![eof $server]} { chunk $server $deadline }
                # A blocking close after EOF collects and checks the exit status.
                fconfigure $server -blocking 1
                close $server
                set server {}
            } on error {message options} {
                catch {exec kill -KILL -- $serverPid}
                catch {fconfigure $server -blocking 1}
                catch {close $server}
                set server {}
                return -options $options "$message\n[log]"
            }
        }
    } finally {
        if {$logPath ne {}} { file delete $logPath; set logPath {} }
    }
}

proc ::readiness::connect {{tls 0} {raw 0} {port {}} {extra {}}} {
    variable clients
    variable childPids
    variable httpPort
    variable tlsPort
    variable openssl
    variable logPath
    if {$port eq {}} { set port [expr {$tls ? $tlsPort : $httpPort}] }
    if {$tls && !$raw} {
        set command [concat $openssl [list s_client -quiet -ign_eof \
            -connect 127.0.0.1:$port -servername localhost] $extra]
        set channel [open [concat | $command [list 2>> $logPath]] r+]
        dict set childPids $channel [pid $channel]
    } else {
        set channel [socket -async 127.0.0.1 $port]
    }
    lappend clients $channel
    binaryChannel $channel
    if {!$tls || $raw} {
        waitFor $channel writable [expr {[clock clicks -milliseconds] + 4000}]
        set error [fconfigure $channel -error]
        check {$error eq {}} "connect failed: $error"
    }
    return $channel
}

proc ::readiness::send {channel data} {
    puts -nonewline $channel $data
    flush $channel
}

proc ::readiness::cpu {} {
    variable serverPid
    variable ticks
    if {!$ticks} { return {} }
    set channel [open /proc/$serverPid/stat r]
    try { set stat [read $channel] } finally { close $channel }
    set fields [split [string trim [string range $stat [expr {[string last ) $stat] + 1}] end]]]
    return [expr {([lindex $fields 11] + [lindex $fields 12]) / double($ticks)}]
}

proc ::readiness::sleeping {} {
    variable serverPid
    after 50
    set before [cpu]
    after 400
    set after [cpu]
    check {![catch {exec kill -0 -- $serverPid}]} "server exited:\n[log]"
    if {$before ne {}} {
        check {$after - $before < 0.20} "server used over half a CPU while awaiting socket readiness"
    }
}

proc ::readiness::response {channel {headOnly 0}} {
    variable pending
    set data {}
    if {[dict exists $pending $channel]} { set data [dict get $pending $channel]; dict unset pending $channel }
    set deadline [expr {[clock clicks -milliseconds] + 4000}]
    while {[set split [string first \r\n\r\n $data]] < 0} {
        set next [chunk $channel $deadline]
        check {$next ne {}} "connection closed before response headers:\n[log]"
        append data $next
    }
    set head [string range $data 0 [expr {$split - 1}]]
    check {[regexp {^HTTP/1\.[01] ([0-9]+)} $head -> status]} "invalid response status"
    set headers {}
    foreach line [lrange [split [string map {\r {}} $head] \n] 1 end] {
        set colon [string first : $line]
        check {$colon > 0} "invalid response header"
        dict lappend headers [string tolower [string range $line 0 [expr {$colon-1}]]] \
            [string trim [string range $line [expr {$colon+1}] end]]
    }
    set body [string range $data [expr {$split + 4}] end]
    if {$headOnly} {
        dict set pending $channel $body
        return [list $status {} $headers]
    }
    if {[dict exists $headers transfer-encoding]} {
        check {![dict exists $headers content-length]} "chunked response also has Content-Length"
        check {[dict get $headers transfer-encoding] eq "chunked"} "unexpected Transfer-Encoding"
        set decoded {}
        while {1} {
            while {[set end [string first \r\n $body]] < 0} {append body [chunk $channel $deadline]}
            check {[scan [string range $body 0 [expr {$end-1}]] %x size] == 1} "invalid chunk size"
            set body [string range $body [expr {$end+2}] end]
            while {[string length $body] < $size + 2} {
                set next [chunk $channel $deadline]
                check {$next ne {}} "truncated chunk"
                append body $next
            }
            check {[string range $body $size [expr {$size+1}]] eq "\r\n"} "missing chunk terminator"
            append decoded [string range $body 0 [expr {$size-1}]]
            set body [string range $body [expr {$size+2}] end]
            if {$size == 0} {break}
        }
        dict set pending $channel $body
        return [list $status $decoded $headers]
    }
    check {[dict exists $headers content-length] && [llength [dict get $headers content-length]] == 1} \
        "expected one Content-Length"
    set length [lindex [dict get $headers content-length] 0]
    while {[string length $body] < $length} {
        set next [chunk $channel $deadline]
        check {$next ne {}} "connection closed after [string length $body] of $length bytes"
        append body $next
    }
    dict set pending $channel [string range $body $length end]
    return [list $status [string range $body 0 [expr {$length - 1}]] $headers]
}

proc ::readiness::expect {channel body {status 200}} {
    lassign [response $channel] actualStatus actualBody
    check {$actualStatus == $status} "expected status $status, got $actualStatus"
    check {$actualBody eq $body} "response body mismatch (expected [string length $body] bytes, got [string length $actualBody])"
}

proc ::readiness::closed {channel} {
    check {[chunk $channel [expr {[clock clicks -milliseconds] + 4000}]] eq {}} "expected connection EOF"
}

proc ::readiness::healthy {{tls 0}} {
    set channel [connect $tls]
    send $channel "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    expect $channel ok
    closeClient $channel
}

proc ::readiness::fragmented {{tls 0}} {
    set channel [connect $tls]
    sleeping
    send $channel "POST /echo HTTP/1.1\r\nHost: local"
    sleeping
    send $channel "host\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nabc"
    after 50
    send $channel def
    expect $channel abcdef
}

proc ::readiness::slowReader {{tls 0}} {
    set channel [connect $tls]
    send $channel "GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n"
    # Do not read the socket/openssl pipe until the 8 MiB response blocks writes.
    sleeping
    expect $channel [string repeat x [expr {8 * 1024 * 1024}]]
}

namespace eval ::readiness {
    namespace import ::tcltest::test
    test readiness-head {HEAD metadata and keepalive across HTTP and HTTPS} \
        -setup start -cleanup stop -body {
            foreach tls {0 1} {
                foreach {path length} {/ 2 /large 8388608 /chunked 12582912 /binary 4 /head-length 12345678901 /head-multi 42} {
                    set channel [connect $tls]
                    send $channel "HEAD $path HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
                    lassign [response $channel 1] status body headers
                    check {$status == 200} "HEAD status mismatch"
                    check {[dict get $headers content-length] eq $length} "HEAD Content-Length mismatch"
                    check {![dict exists $headers transfer-encoding]} "HEAD must not send chunks"
                    check {[dict get $pending $channel] eq {}} "HEAD sent body bytes"
                    send $channel "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    expect $channel ok
                    closed $channel
                    closeClient $channel
                }
            }
        } -result {}
    test readiness-head-gzip {HEAD preserves the compressed GET representation length} \
        -setup start -cleanup stop -body {
            set channel [connect]
            send $channel "GET /large HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n"
            lassign [response $channel] status body headers
            set length [string length $body]
            check {[dict get $headers content-encoding] eq "gzip"} "GET was not compressed"
            send $channel "HEAD /large HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
            lassign [response $channel 1] status body headers
            check {[dict get $headers content-encoding] eq "gzip"} "HEAD lost encoding"
            check {[dict get $headers content-length] eq $length} "compressed HEAD length mismatch"
            check {[dict get $pending $channel] eq {}} "HEAD sent body bytes"
            closed $channel
        } -result {}
    test readiness-framing {server emits one correct framing header} \
        -setup start -cleanup stop -body {
            set channel [connect]
            send $channel "GET /framing HTTP/1.1\r\nHost: localhost\r\n\r\n"
            expect $channel ok
        } -result {}
    test readiness-repeated-headers {each multi-value header has its own field line} \
        -setup start -cleanup stop -body {
            set channel [connect]
            send $channel "GET /cookies HTTP/1.1\r\nHost: localhost\r\n\r\n"
            lassign [response $channel] status body headers
            check {$status == 200 && $body eq "ok"} "response mismatch"
            check {[dict get $headers set-cookie] eq [list {a=1; Path=/} {b=2; Expires=Wed, 21 Oct 2037 07:28:00 GMT}]} \
                "cookies must remain separate header fields"
        } -result {}
    test readiness-response-arguments {deferred responses accept the optional encoding argument being omitted} \
        -setup start -cleanup stop -body {
            for {set i 0} {$i < 30} {incr i} {
                set channel [connect]
                send $channel "GET /deferred HTTP/1.1\r\nHost: localhost\r\n\r\n"
                expect $channel ok
                closeClient $channel
            }
        } -result {}
    test readiness-chunked {large responses omit Content-Length when chunked} \
        -setup start -cleanup stop -body {
            set channel [connect]
            send $channel "GET /chunked HTTP/1.1\r\nHost: localhost\r\n\r\n"
            lassign [response $channel] status body headers
            check {$status == 200} "chunked status mismatch"
            check {[dict get $headers transfer-encoding] eq "chunked"} "expected chunked response"
            check {$body eq [string repeat x 12582912]} "chunked body mismatch"
        } -result {}
    test readiness-chunked-request {HTTP and TLS decode binary chunks and reset framing on keepalive} \
        -setup start -cleanup stop -body {
            set values {}
            for {set i 0} {$i < 256} {incr i} {lappend values $i}
            set binary [string repeat [binary format c* $values] 257]
            foreach tls {0 1} {
                set channel [connect $tls]
                send $channel "PUT /echo-binary HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: ChUnKeD \t\r\n\r\n"
                send $channel "[format %x [string length $binary]];name=value\r\n$binary\r\n1\r\nx\r\n0\r\nX-Checksum: ignored\r\n\r\n"
                expect $channel ${binary}x
                send $channel "POST /echo HTTP/1.1\r\nConnection: keep-alive\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nfixed"
                expect $channel fixed
                send $channel "POST /echo HTTP/1.1\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                expect $channel {}
                send $channel "GET / HTTP/1.1\r\nConnection: close\r\n\r\n"
                expect $channel ok
                closed $channel
            }
        }
    test readiness-chunked-fragments {chunk sizes, data, delimiters and trailers can span reads} \
        -setup start -cleanup stop -body {
            foreach tls {0 1} {
                set channel [connect $tls]
                send $channel "POST /echo HTTP/1.1\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
                foreach part [list 3 \r \n a bc \r "\n0\r" "\nX-Checksum: value\r" \n \r \n] {
                    send $channel $part
                    after 10
                }
                expect $channel abc
            }
        }
    test readiness-chunked-content-encoding {HTTP decoding preserves the inner AWS chunk framing} \
        -setup start -cleanup stop -body {
            set inner "3\r\n[binary format H* 00ff01]\r\n0\r\nx-amz-checksum-crc32: fake\r\n\r\n"
            set channel [connect]
            send $channel "PUT /echo-binary HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Encoding: aws-chunked\r\nTransfer-Encoding: chunked\r\n\r\n[format %x [string length $inner]]\r\n$inner\r\n0\r\n\r\n"
            expect $channel $inner
        }
    test readiness-chunked-invalid {ambiguous framing and malformed chunks return 400 and close} \
        -setup start -cleanup stop -body {
            foreach {headers body} [list \
                    "Transfer-Encoding: chunked\r\nContent-Length: 5" "0\r\n\r\n" \
                    "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked" "0\r\n\r\n" \
                    {Transfer-Encoding: gzip, chunked} "0\r\n\r\n" \
                    {Transfer-Encoding: chunked, gzip} "0\r\n\r\n" \
                    {Transfer-Encoding: chunked} "z\r\n" \
                    {Transfer-Encoding: chunked} "1garbage\r\nx\r\n0\r\n\r\n" \
                    {Transfer-Encoding: chunked} "FFFFFFFFFFFFFFFFF\r\n" \
                    {Transfer-Encoding: chunked} "1\nx\r\n0\r\n\r\n" \
                    {Transfer-Encoding: chunked} "1\r\nx!!" \
                    {Transfer-Encoding: chunked} "0\r\ninvalid trailer\r\n\r\n" \
                    {Transfer-Encoding: chunked} "0\r\nBad Name: value\r\n\r\n" \
                    {Transfer-Encoding: chunked} "1;[string repeat x 8192]\r\n"] {
                set channel [connect]
                send $channel "POST /echo HTTP/1.1\r\nConnection: keep-alive\r\n$headers\r\n\r\n$body"
                lassign [response $channel] status
                check {$status == 400} "invalid chunked request returned $status"
                closed $channel
            }
            healthy
        }
    test readiness-chunked-deadline {incomplete chunk data and trailers expire without dispatch} \
        -setup start -cleanup stop -body {
            foreach body [list "4\r\nabc" "0\r\nX-Trailer: value\r\n"] {
                set channel [connect]
                send $channel "POST /echo HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n$body"
                expect $channel {Bad Request} 400
                closed $channel
            }
            healthy
        }
    test readiness-fragmented-http {idle and fragmented HTTP sleeps and resumes} \
        -setup start -cleanup stop -body { fragmented } -result {}
    test readiness-fragmented-tls {idle and fragmented TLS sleeps and resumes} \
        -setup start -cleanup stop -body { fragmented 1 } -result {}
    test readiness-buffered-tls {TLS request spans multiple buffered records} \
        -setup start -cleanup stop -body {
            set channel [connect 1]
            set body [string repeat 0123456789abcdef 4096]
            send $channel "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 65536\r\n\r\n$body"
            expect $channel $body
        } -result {}
    test readiness-buffered-keepalive {two TLS records arrive without further client traffic} \
        -setup start -cleanup stop -body {
            set port [proxy::start $tlsPort]
            set channel [connect 1 0 $port {-tls1_2 -max_send_frag 512}]
            set first "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nX-Pad: "
            append first [string repeat x [expr {512 - [string length $first] - 4}]] \r\n\r\n
            send $channel "${first}POST /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nsecond"
            expect $channel ok
            expect $channel second
            closed $channel
            check {$proxy::error eq {}} "TLS proxy failed: $proxy::error"
            check {$proxy::released} "TLS proxy did not deliver two application records together"
        } -result {}
    test readiness-split-header {header terminator can straddle any read boundary} \
        -setup start -cleanup stop -body {
            foreach split {1 2 3} {
                set channel [connect]
                set marker \r\n\r\n
                send $channel "GET / HTTP/1.1\r\nHost: localhost[string range $marker 0 [expr {$split - 1}]]"
                after 50
                send $channel [string range $marker $split end]
                expect $channel ok
                closeClient $channel
            }
        } -result {}
    test readiness-read-deadline {incomplete HTTP body times out without other requests} \
        -setup start -cleanup stop -body {
            set channel [connect]
            send $channel "POST /echo HTTP/1.1\r\nContent-Length: 6\r\n\r\na"
            sleeping
            expect $channel {Bad Request} 400
            healthy
        } -result {}
    test readiness-handshake-deadline {silent TLS peer sleeps and expires} \
        -setup start -cleanup stop -body {
            set channel [connect 1 1]
            sleeping
            closed $channel
            healthy 1
        } -result {}
    test readiness-keepalive {HTTP and TLS keepalive reuse then idle expiry} \
        -setup start -cleanup stop -body {
            foreach tls {0 1} {
                set channel [connect $tls]
                set request "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
                send $channel $request
                expect $channel ok
                after 50
                send $channel [string range $request 0 4]
                after 50
                send $channel [string range $request 5 end]
                expect $channel ok
                sleeping
                closed $channel
                closeClient $channel
                healthy $tls
            }
        } -result {}
    test readiness-slow-http {blocked HTTP response resumes when client reads} \
        -setup start -cleanup stop -body { slowReader } -result {}
    test readiness-slow-tls {blocked TLS response resumes when client reads} \
        -setup start -cleanup stop -body { slowReader 1 } -result {}
    test readiness-nested-timeout {timeout during a handler's nested event loop is safe} \
        -setup start -cleanup stop -body {
            set channel [connect]
            send $channel "GET /nested HTTP/1.1\r\nHost: localhost\r\n\r\n"
            closed $channel
            after 700
            healthy
        } -result {}
    test readiness-disconnects {disconnects and errors leave no stale connection work} \
        -setup start -cleanup stop -body {
            for {set i 0} {$i < 8} {incr i} {
                foreach prefix [list {} GE "invalid request\r\n\r\n"] {
                    set channel [connect]
                    if {$prefix ne {}} { send $channel $prefix }
                    closeClient $channel
                }
                set channel [connect 1 1]
                send $channel {not a TLS record}
                closeClient $channel
            }
            foreach tls {0 1} {
                set channel [connect $tls]
                send $channel "GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n"
                after 100
                closeClient $channel
            }
            healthy
            healthy 1
        } -result {}
}

set failed $::tcltest::numTests(Failed)
::tcltest::cleanupTests
exit [expr {$failed > 0}]
