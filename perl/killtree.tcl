#!/home/embtest/embtest/tcl_setuid

if {[llength $argv] < 1} {
    puts {Kills all processes started by <pid>}
    puts {Usage: killtree.tcl <pid>}
    exit 1
}

proc killtree {pid} {
    if {$pid <= 1} {
	# Never kill pid 0 or 1!
	return
    }
    if [catch {set childpids [exec /bin/ps h --ppid $pid -o pid]} errmsg] {
	# this can error if empty, this is ok, just continue
    } else {
	foreach childpid $childpids {
	    killtree $childpid
	}
    }
    puts -nonewline " $pid"
    catch "exec /bin/kill -9 $pid"
}

killtree [lindex $argv 0]

exit 0
