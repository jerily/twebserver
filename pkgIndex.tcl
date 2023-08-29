set dir [file dirname [info script]]

package ifneeded twebserver 0.1 [list load [file join $dir libtwebserver.so]]
