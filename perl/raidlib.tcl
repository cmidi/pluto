
# Log file web link
set LOG_WEB_LINK "http://raid.acmepacket.com/anvildb/displayresults.php?tag="
set LOG_ARCHIVE_LINK "http://raid.acmepacket.com/anvildb/displayarchive.php?file=/home/raid/raid/logs/"

#
# Keyed List handlers
#
proc klfind {kl key} {
    set index 0
    foreach entry $kl {
        if {[string match $key [lindex $entry 0]]} {
            return $index
        }
        incr index
    }
    return {}
}

proc klget {kl key} {
    set index [klfind $kl $key]
    if [llength $index] {
        return [lindex [lindex $kl $index] 1]
    }
    return {}
}

proc klset {kl key value} {
    upvar $kl kllocal
    set index [klfind $kllocal $key]
    if [llength $index] {
        set kllocal [lreplace $kllocal $index $index [list $key $value]]
    } else {
        lappend kllocal [list $key $value]
    }
}

proc kldel {kl key} {
    upvar $kl kllocal
    set index [klfind $kllocal $key]
    if [llength $index] {
        set kllocal [lreplace $kllocal $index $index]
    }
}

proc klkeys {kl} {
    set retlist {}
    foreach entry $kl {
        lappend retlist [lindex $entry 0]
    }
    return $retlist
}

#
# Logging handlers
#

proc timestamp {{t 0}} {
    if {$t == 0} {
	set t [clock seconds]
    }
    
    return [clock format $t -format "%m/%d/%y %H:%M:%S" ]
}

proc log_msg {message {prefix {INFO}}} {
    puts "[timestamp] $prefix: $message"
}

proc email {to from subject msg} {
    if [catch {
	if {![llength $from]} {
	    set from [lindex [split $to " ,;"] 0]
	}
#	exec /home/raid/raid/mail.tcl $to $from $subject $msg
    } errmsg] {
	log_msg "Error sending mail: $errmsg" ERROR
    }
}

proc parse_runfile {runfile} {
    set testinfo {}

    if {[catch {
	set fd [open $runfile]
    } errmsg]} {
	log_msg "Could not open runfile $runfile: $errmsg" ERROR
	return {}
    }
    while {![eof $fd]} {
	set runline [gets $fd]
	if [regexp {^[ \t]*END[ \t]*} $runline] {
	    # Completed with parsing runfile
	    close $fd
	    return $testinfo
	}
	if [regexp {^[ \t]*([A-Za-z0-9_:-]+)[ \t]*=(.*)$} $runline - key value] {
            regsub -all {^"|"$} $value {} value
	    # Add parameter to list
	    klset testinfo $key $value
	}		
    }

    close $fd
    # no END in file, not complete or invalid
    return {}

}

proc testinfo_string {testinfo {testid {}}} {
    set str ""

    append str "User: [klget $testinfo USER]\n"
    set img [klget $testinfo IMAGE]
    regsub "${testid}_" [klget $testinfo IMAGE] "" img
    append str "Image: $img\n"
    append str "Submitted: [clock format [klget $testinfo SUBMITTIME] -format "%m/%d/%y %H:%M:%S" ]\n"
    append str "SD Logging: [klget $testinfo LOGGING]\n"
    append str "Packet Capure: [klget $testinfo CAPTURE]\n"
    append str "Anvil Tracing: [klget $testinfo TRACING]\n"
    append str "Run Failures: [klget $testinfo RUN_FAILS]\n"

    return $str
}
