#!/usr/bin/expect
#
# Edited by Scott McCulley for use with embtest

source raidlib.tcl

if {[llength $argv] < 5} {
    puts {Usage: submit.tcl <testbed> <ftphost> <image> <email> <suitelist> [testid]}
    exit 1
}

#
# Test run file
# Defines test submission parameters
#

#USER=mpiecuch
#IMAGE=mpiecuch_2008-07-15-10-36-34_kyle.gz
#SUBMITTIME=1216132594
#PRIORITY=3
#TESTSUITE=BACKUP_ARCHIVE
#SUBTEST:BACKUP_ARCHIVE=BACKUP-RESTORE
#PATH:BACKUP_ARCHIVE=BACKUP_ARCHIVE/BACKUP_ARCHIVE.tcl
#EMAIL=mpiecuch@acmepacket.com

# Must finish with END
#END

if [catch {
    set testbed [lindex $argv 0]
    set ftphost [lindex $argv 1]
    set image [lindex $argv 2]
    set email [lindex $argv 3]
    set suite_selection_id [lindex $argv 4]
    set suites [lindex $argv 5]
    regsub -all {\{} $suites {} suites
    regsub -all {\}} $suites {} suites

    set testid [lindex $argv 6]
    set curimgtime [lindex $argv 7]
    set selectedtests {}
    set subtests ""

    set username "nightly"
    set priority 5
    set submittime [clock seconds]

    puts "Test ID: $testid"
    puts "Suite Selection ID: $suite_selection_id"
    puts "Suites: $suites"

    if {![llength $testid]} {
	set testid "${username}_[clock format $submittime -format {%Y-%m-%d-%H-%M-%S}]"
    }

    if [catch {
	source configs/embtest.cfg
    } errmsg] {
	puts "Error sourcing configs/embtest.cfg: $errmsg"
	exit 1
    }

    if {[lsearch -exact $cfg_testbeds $testbed] == -1} {
	puts "Error: invalid testbed $testbed"
	exit 1
    }

    if [catch {
	exec ./imageftp.exp $ftphost $image $cfg_image_dir($testbed)/${testid}_$image
    } errmsg] {
	puts "Error in ftp image: $errmsg"
	exit 1
    }
 
    set suites [split $suites "\t"]
    puts "Building Test Suites Hash"
    foreach suite $suites {
        set suite [split $suite ":"]

        puts "Test Suite: [lindex $suite 0]"

        klset selectedtests [lindex $suite 0] ""
    }

    puts "Populating subtests"
    foreach suite $suites {
        set suite [split $suite ":"]

        puts "Test Suite: [lindex $suite 0]"

        set subtests [klget $selectedtests [lindex $suite 0]]

        puts "Subtests: $subtests"
        if {[llength $suite] == 2} {
            if {$subtests != ""} {
                append subtests " "
            }
            append subtests [lindex $suite 1]
        } else {
            puts "List Length: [llength $suite]"
        }

        puts "Test Suite Subtests: $subtests"

        klset selectedtests [lindex $suite 0] $subtests

    }

    if [catch {
	set fd [open $cfg_run_dir($testbed)/${testid}.run w]
	puts $fd "USER=\"$username\""
	puts $fd "IMAGE=\"${testid}_$image\""
	puts $fd "SUBMITTIME=$submittime"
        puts $fd "NOTES=\"Nightly: ${image} - Built: [clock format $curimgtime]\""
	puts $fd "PRIORITY=\"$priority\""
        puts $fd "SUITESELECTIONID=\"$suite_selection_id\""
	puts $fd "TESTSUITE=\"[klkeys $selectedtests]\""
	foreach testsuite [split [klkeys $selectedtests] " "] {
            if {[klget $selectedtests $testsuite] != ""} {
                puts $fd "SUBTEST:$testsuite=[klget $selectedtests $testsuite]"
            }
	}
	puts $fd "EMAIL=$email"
	puts $fd "END"
	close $fd
    } errmsg] {
	puts "Error writing run file: $errmsg"
	exit 1
    }
} errmsg] {
    puts "Error in submit: $errmsg"
    exit 1
}



