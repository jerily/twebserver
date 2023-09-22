 proc accept {chan addr port} {           ;# Make a proc to accept connections
     puts "$addr:$port says [gets $chan]" ;# Receive a string
     puts -nonewline $chan "HTTP/1.1 200 OK\nContent-Length:0\n\n"                   ;# Send a string
     close $chan                          ;# Close the socket (automatically flushes)
 }                                        ;#
 socket -server accept 12345              ;# Create a server socket
 vwait forever
