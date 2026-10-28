# Deliver two distinct TLS 1.2 application records in one socket write. This
# exercises OpenSSL read-ahead without depending on TCP packet coalescing.
namespace eval ::readiness::proxy {
    variable listener ""
    variable client ""
    variable backend ""
    variable backendPort 0
    variable incoming ""
    variable held ""
    variable heldCount 0
    variable released 0
    variable error ""
}

proc ::readiness::proxy::stop {} {
    variable listener
    variable client
    variable backend
    foreach name {listener client backend} {
        set channel [set $name]
        set $name ""
        if {$channel ne ""} {
            catch {fileevent $channel readable {}}
            catch {close $channel}
        }
    }
}

proc ::readiness::proxy::start {port} {
    variable listener
    variable backendPort
    variable incoming
    variable held
    variable heldCount
    variable released
    variable error
    stop
    set backendPort $port
    set incoming ""
    set held ""
    set heldCount 0
    set released 0
    set error ""
    set listener [socket -server ::readiness::proxy::accept -myaddr 127.0.0.1 0]
    return [lindex [fconfigure $listener -sockname] end]
}

proc ::readiness::proxy::failed {message} {
    variable error
    set error $message
    stop
}

proc ::readiness::proxy::accept {channel address port} {
    variable listener
    variable client
    variable backend
    variable backendPort
    set client $channel
    if {[catch {
        close $listener
        set listener ""
        set backend [socket -async 127.0.0.1 $backendPort]
        foreach stream [list $client $backend] {
            fconfigure $stream -translation binary -buffering none -blocking 0
        }
        fileevent $client readable ::readiness::proxy::fromClient
        fileevent $backend readable ::readiness::proxy::fromBackend
    } message]} {
        failed $message
    }
}

proc ::readiness::proxy::fromClient {} {
    variable client
    variable backend
    variable incoming
    variable held
    variable heldCount
    variable released
    if {[catch {
        append incoming [read $client 65536]
        while {[string length $incoming] >= 5} {
            binary scan $incoming cu@3Su type length
            set size [expr {5 + $length}]
            if {[string length $incoming] < $size} { break }
            set record [string range $incoming 0 [expr {$size - 1}]]
            set incoming [string range $incoming $size end]
            # TLS 1.2 keeps handshake records distinct from application data.
            if {!$released && $type == 23} {
                append held $record
                incr heldCount
                if {$heldCount < 2} { continue }
                set record $held
                set held ""
                set released 1
            }
            puts -nonewline $backend $record
            flush $backend
        }
        if {[eof $client]} { stop }
    } message]} {
        failed $message
    }
}

proc ::readiness::proxy::fromBackend {} {
    variable client
    variable backend
    if {[catch {
        set data [read $backend 65536]
        if {$data ne ""} {
            puts -nonewline $client $data
            flush $client
        }
        if {[eof $backend]} { stop }
    } message]} {
        failed $message
    }
}
