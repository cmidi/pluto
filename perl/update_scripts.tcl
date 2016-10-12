#!/usr/bin/expect

if {[catch {

    set ROOT "/home/raid"
    set SCRIPT_PATH "$ROOT/QA/scripts"
    set SCENARIO_PATH "$ROOT/QA/scenarios"
    set REGRESSION_PATH "$ROOT/QA/regression"

    proc svnupdate {} {
	set output [exec svn update]
	set lines [split $output "\n"]
	set conflict 0
	foreach line $lines {
	    if [regexp "^C (.+)" $line - file_name] {
		puts "Conflict with file $file_name"
		file delete -force $file_name
	    	set conflict 1
	    } else {
		puts $line
	    }
	}
	if { $conflict == 1 } {
            puts "Conflict(s) exist.  Executing svn update again."
	    set output [exec svn update]
            puts $output
	}
    }

    #
    # Main
    #

    set current_dir [pwd]

    puts "Changing to directory $SCRIPT_PATH"
    cd $SCRIPT_PATH
    svnupdate
    cd $current_dir
    
    puts "Changing to directory $SCENARIO_PATH"
    cd $SCENARIO_PATH
    svnupdate
    cd $current_dir
    
    puts "Changing to directory $REGRESSION_PATH"
    cd $REGRESSION_PATH
    svnupdate
    cd $current_dir

    puts "\nScripts updated successfully."
    
    global env 
    set env(ANVIL_HOME) /usr/local/anvil
    set env(AUTO_HOME) /home/raid/raid/testbeds/SD2/SD2-grub
    set env(ANVIL_DYNAMICIP) /home/raid/raid/testbeds/SD2/SD2-grub/setups/SD2-grub.ip
    set env(ANVIL_RCFILE) /home/raid/raid/testbeds/SD2/SD2-grub/setups/SD2-grub.rc
    set env(AUTO_RIGSETUP) /home/raid/raid/testbeds/SD2/SD2-grub/setups/SD2-grub.setup
 
    puts "\nCreating tests.ini"
    set status [catch {exec $ROOT/raid/gen-sub-tests.tcl $ROOT/raid/tests.ini 2>@ stderr} result]

    if { $status == 0 } {
	puts "\nUpdating Raid DB with test scenarios"
	file copy -force $ROOT/raid/tests.ini $ROOT/raid/configs/tests.ini
	set timeout 60
	spawn telnet localhost 80
	expect {Escape character is '^]'.}
	send "GET http://raid.acmepacket.com/raid/update_suitesdb.php\r"
	expect {All common test suite selections updated}
	interact -f -re "(.*)\r" return
#	exec telnet localhost 80 >@ stdout << "GET http://raid.acmepacket.com/raid/update_suitesdb.php\r"
    } else {
	puts "\ngen-sub-tests did not exit cleanly"
    }

    file delete tests.ini
    
    puts "\nDone."

    exit 0

} errmsg]} {
    puts "\nInternal error: $errmsg"
    exit 1
}
