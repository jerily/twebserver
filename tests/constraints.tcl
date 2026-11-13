package require tcltest 2
namespace eval ::twebserver_test_constraints {
    if {![info exists checked]} {
        set checked 1
        set available [expr {![catch {package require tpathexp 1.2.0} reason]}]
        ::tcltest::testConstraint tpathexp $available
        if {!$available} {
            puts stderr "WARNING: tpathexp 1.2.0 is unavailable; routing tests will be skipped ($reason)."
        }
    }
}
