set dir [file dirname [info script]]

package ifneeded tws 0.1 [list load [file join $dir build libtws.so]]
