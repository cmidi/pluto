#!/home/embtest/embtest/tcl_setuid

if {[llength $argv] < 1} {
    puts {chowns provided file/directory}
    puts {Usage: chown_path.tcl <user> <group> <path>}
    exit 1
}

puts "Entered chown_path script\n"

if {[catch {
    exec chown -R [lindex $argv 0]:[lindex $argv 1] [lindex $argv 2]
} errmsg]} {
    puts "Caught error: $errmsg"
}

exit 0
