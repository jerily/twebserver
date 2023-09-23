package require tcltest
namespace import -force ::tcltest::test

if { [llength $argv] == 0 } {
    puts stderr "Usage: $argv0 libdir"
    exit 1
}

set auto_path [linsert $auto_path 0 [lindex $argv 0]]
set argv [lrange $argv 1 end]

::tcltest::configure -singleproc true -testdir [file dirname [info script]]

exit [::tcltest::runAllTests]