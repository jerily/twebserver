 proc accept {chan addr port} {           ;# Make a proc to accept connections
     puts "$addr:$port says [gets $chan]" ;# Receive a string
     puts $chan goodbye                   ;# Send a string
     close $chan                          ;# Close the socket (automatically flushes)
 }                                        ;#
 socket -server accept 12345              ;# Create a server socket
 vwait forever 
