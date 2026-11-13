# Deprecated 1.x router API. Matching is supplied entirely by tpathexp.
# New applications should use tpathexp directly; see examples/example-best-with-router.tcl.
namespace eval ::twebserver::compat {
    variable next_id 0
    variable routers {}

    proc require_router {id} {
        variable routers
        if {![dict exists $routers $id]} {error "router handle not found: $id"}
        return [dict get $routers $id native]
    }

    proc destroy {id} {
        variable routers
        if {![dict exists $routers $id]} {return}
        set state [dict get $routers $id]
        dict unset routers $id
        [dict get $state native] destroy
        foreach command [dict get $state commands] {
            if {[namespace which -command $command] ne {}} {rename $command {}}
        }
    }

    proc command_trace {id old new operation} {
        variable routers
        if {![dict exists $routers $id]} {return}
        if {$operation eq "delete"} {
            destroy $id
        } else {
            set commands [dict get $routers $id commands]
            set index [lsearch -exact $commands $old]
            dict set routers $id commands [lreplace $commands $index $index $new]
        }
    }

    proc variable_trace {id name1 name2 operation} {
        if {$operation eq "unset"} {
            destroy $id
        } else {
            if {$name2 eq {}} {upvar 1 $name1 value} else {upvar 1 ${name1}($name2) value}
            set value $id
            error "var is read-only"
        }
    }

    proc enter {guards name named wildcard ctx req} {
        if {$named} {dict set ctx route_name $name}
        if {$wildcard} {dict set req pathParameters {}}
        foreach guard $guards {set req [{*}$guard $ctx $req]}
        return $req
    }

    proc invoke {handler name named wildcard req ctx params} {
        if {$named} {dict set ctx route_name $name}
        if {$wildcard} {dict set req pathParameters {}}
        return [::twebserver::invoke_handler $handler $req $ctx $params]
    }

    proc dispatch {id ctx req} {
        ::twebserver::process_conn [require_router $id] $ctx $req
    }
}

proc ::twebserver::create_router {args} {
    set command {}
    if {[llength $args] >= 2 && [lindex $args 0] eq "-command_name"} {
        set command [lindex $args 1]
        set args [lrange $args 2 end]
    }
    if {[llength $args] > 1 || ([llength $args] && [string match -* [lindex $args 0]])} {
        error {wrong # args: should be "twebserver::create_router ?-command_name command? ?varname?"}
    }
    package require tpathexp 1.2.0
    set native [namespace which -command [::tpathexp::router]]
    set id _TWS_ROUTER_COMPAT_[incr ::twebserver::compat::next_id]
    set commands [list ::$id]
    if {$command ne {}} {
        if {![string match ::* $command]} {
            set command [string trimright [uplevel 1 {namespace current}] :]::$command
        }
        lappend commands $command
    }
    dict set ::twebserver::compat::routers $id \
        [dict create native $native routes {} commands $commands]
    foreach name $commands {
        interp alias {} $name {} ::twebserver::compat::dispatch $id
        trace add command $name {rename delete} [list ::twebserver::compat::command_trace $id]
    }
    if {[llength $args]} {
        upvar 1 [lindex $args 0] value
        unset -nocomplain value
        set value $id
        trace add variable value {write unset} [list ::twebserver::compat::variable_trace $id]
    }
    return $id
}

proc ::twebserver::add_route {args} {
    set prefix 0
    set nocase 0
    set strict 0
    set guards {}
    set name {}
    set named 0
    while {[llength $args] && [string match -* [lindex $args 0]]} {
        set option [lindex $args 0]
        set args [lrange $args 1 end]
        switch -- $option {
            -- {break}
            -prefix {set prefix 1}
            -nocase {set nocase 1}
            -strict {set strict 1}
            -name - -guard_proc_list {
                if {![llength $args]} {error "missing value for $option"}
                if {$option eq "-name"} {
                    set name [lindex $args 0]
                    set named 1
                } else {set guards [lindex $args 0]}
                set args [lrange $args 1 end]
            }
            default {error "unknown option: $option"}
        }
    }
    if {[llength $args] != 4} {
        error {wrong # args: should be "twebserver::add_route ?options? router method path handler"}
    }
    if {$prefix && $strict} {error "add_route: option -prefix and -strict are mutually exclusive"}
    lassign $args id method path handler
    set native [::twebserver::compat::require_router $id]
    set wildcard [expr {$path eq "*" || ($path eq "/" && $prefix)}]
    set expression $path
    if {$wildcard} {set expression {:__compat_path(.*)}}
    # The 1.x literal matcher required exact paths even without -strict.
    set type [expr {[regexp {[.+*?=^!:$\{\}()\[\]|]} $path] ? "regexp" : "exact"}]
    set flags [list -strict [expr {$strict || $type eq "exact"}] -nocase $nocase -end [expr {!$prefix}]]
    set matcher [::tpathexp::compile {*}$flags -- $expression]
    try {set pattern [$matcher pattern]} finally {$matcher destroy}
    $native add $method $expression \
        [list ::twebserver::compat::invoke $handler $name $named $wildcard] {*}$flags \
        -enter_proc [list ::twebserver::compat::enter $guards $name $named $wildcard]
    set routes [dict get $::twebserver::compat::routers $id routes]
    lappend routes [dict create http_method $method path $path proc_name $handler type $type \
        option_prefix $prefix option_nocase $nocase option_strict $strict \
        fast_star [expr {$path eq "*"}] fast_slash [expr {$path eq "/" && $prefix}] pattern $pattern]
    dict set ::twebserver::compat::routers $id routes $routes
    return
}

proc ::twebserver::add_middleware {args} {
    set enter {}
    set leave {}
    while {[llength $args] && [string match -* [lindex $args 0]]} {
        set option [lindex $args 0]
        if {$option ni {-enter_proc -leave_proc}} {error "unknown option: $option"}
        if {[llength $args] < 2} {error "missing value for $option"}
        if {$option eq "-enter_proc"} {set enter [lindex $args 1]} else {set leave [lindex $args 1]}
        set args [lrange $args 2 end]
    }
    if {[llength $args] != 1} {
        error {wrong # args: should be "twebserver::add_middleware ?-enter_proc prefix? ?-leave_proc prefix? router"}
    }
    if {$enter eq {} && $leave eq {}} {error "add_middleware: at least one enter or leave proc is required"}
    set id [lindex $args 0]
    set native [::twebserver::compat::require_router $id]
    $native add_middleware -enter_proc $enter -leave_proc $leave
    return
}

proc ::twebserver::info_routes {id} {
    ::twebserver::compat::require_router $id
    return [dict get $::twebserver::compat::routers $id routes]
}
