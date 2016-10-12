#!/usr/bin/expect

package require smtp
package require mime

global argv

exit 0

if {[llength $argv] < 3} {
    puts {Usage: mail.tcl <to> <from> <subject> [body]}
    exit 1
}
set rawto [lindex $argv 0]
set from [lindex $argv 1]
set subject [lindex $argv 2]
puts "rawto: $rawto from: $from subject: $subject"
set body {}
if {[llength $argv] > 3} {
    set body [lindex $argv 3]
} else {
    while {![eof stdin]} {
	append body "[gets stdin]\n"
    }
}

puts "body: $body"

set fromparts [split $from @]
if {[llength $fromparts] == 1} {
    set from "${from}@acmepacket.com"
}

foreach to [split $rawto " ;,"] {
    if {![llength $to]} {continue}

    set toparts [split $to @]
    if {[llength $toparts] == 1} {
	set to "${to}@acmepacket.com"
    } else {
	if {[string compare [lindex $toparts 1] "acmepacket.com"]} {continue}
    }

    set server etmail.acmepacket.com

    set message [mime::initialize -canonical "text/plain" -string "$body"]

    smtp::sendmessage $message -servers $server \
	-header [list To $to] \
	-header [list From $from] \
	-header [list Subject $subject]

#	-debug 1 \

    mime::finalize $message
}

exit 0
