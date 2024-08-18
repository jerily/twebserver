package require tcltest
namespace import -force ::tcltest::test

::tcltest::configure {*}$argv -singleproc true -testdir [file dirname [info script]]

exit [::tcltest::runAllTests]