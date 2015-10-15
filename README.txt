This library provides helper functions for accessing a javad device over a stream, and provides an example about how to consume one of the binary messages that the unit can send
.

Now supports starting/stopping/downloading log files!

I've also added a wrapper for starting and stopping the positoin averaging process


If using ccl, there is a convenience function for opening a socket and logging into the javad unit in java-connect.  otherwise bring your own socket.  I'll get around to learning usocket some day....

A full usage example is provided in javad-get-velocity.  This function assumes that the input stream is a logged in javad, and then clears the input on the stream (standard common lisp functions to do this didn't seem to work and I don't know why, so I just had to call explicit read).

javad-generic-command is just a thin wrapper for shipping text commands to the unit and sending a clrf, similar to sitting on telnet.

There is a generic response message class that consists of the message header, the length of the data field, and a slot for the data.

javad-parse-message will attempt to parse a generic message from a logged in javad stream.  right now it assumes that the beginning of a valid message is next to be read from the input stream.  A smarter handler would read to the beginnig of a valid message and then also return a list of all messages found, but for now I just read in the first message available and throw away the rest of the data if there is any.

javad-parse-vg-message takes a generic message and assumes its a geodetic velocity message, and parses it further, overwriting the input message object's data field with the appropriate values.

TODO.
provide convenience functions for consuming opus email in order to prep commands for setting the apc and reference point for the reciever.
make an application on top of all of this, make it more user friendly?  socket times out due to inactivity, and spurious output must be manually cleared.
