#!/bin/bash
# the next line restarts using anvil \
exec /usr/local/anvil/anvil --logdir=$4/logs "$0" "$@"

source raidlib.tcl
source database.tcl


global argv
set run_id [lindex $argv 0]
set suite [lindex $argv 1]
set subtests [lindex $argv 2]
set stbdir [lindex $argv 3]

set env(RUN_ID) "$run_id"

log_msg "Current Env Path: $env(PATH)" CHILD

log_msg "Run ID:         $run_id" CHILD
log_msg "Test Suite:     $suite" CHILD
log_msg "Subtests:       $subtests" CHILD
log_msg "Subtestbed Dir: $stbdir" CHILD
log_msg ""

catch {cd $stbdir}
log_msg "Current working directory: [pwd]"
log_msg ""

set db [embtestdb_connect]

set q "SELECT case_id"
append q " FROM test_case"
append q " WHERE suite_id = (SELECT suite_id from test_suite WHERE suite_name = 'EmbTest_Framework' LIMIT 1)"
append q " AND case_name = 'embtest_anvil'"
append q " LIMIT 1"

mysqlsel $db $q

mysqlmap $db {case_id} {
    set embtest_anvil_case_id $case_id
    break
}

log_msg "EmbTest Framework Information"
log_msg "embtest_anvil case_id: $embtest_anvil_case_id"
log_msg ""

# Catch all for all errors
if {[catch {

    set q "SELECT suite_id, path, requires, suite_config, suite_setup, visible"
    append q " FROM test_suite WHERE suite_name = '$suite'"
    append q " LIMIT 1"
    mysqlsel $db $q

    mysqlmap $db {suite_id path requires suite_config suite_setup visible} {
        set suite_id $suite_id
        set suite_path $path
        set suite_requires $requires
        set suite_config $suite_config
        set suite_setup $suite_setup
        set suite_visible $visible
        break
    }

    log_msg "Test Suite Information"
    log_msg "Suite ID:              $suite_id"
    log_msg "Path:                  $suite_path"
    log_msg "Requires:              $suite_requires"
    log_msg "Suite Config:          $suite_config"
    log_msg "Suite Setup:           $suite_setup"
    log_msg "Visible:               $suite_visible"
    log_msg ""

    # In order to simulate the same nomenclature of [dut1.tsport] for suite information
    # create some tcl proc's
    proc suite.id {} [list return $suite_id]
    proc suite.path {} [list return "scripts/$suite_path/"]
    proc suite.requires {} [list return $suite_requires]
    proc suite.config {} [list return $suite_config]
    proc suite.setup {} [list return $suite_setup]
    proc suite.visible {} [list return $suite_visible]

    if {$suite_visible == 0} {
        log_msg "Test Suite $suite is currently disabled"
        puts stderr "\nEMBTESTOK\n\n"
        anvil cleanup pop -all
        exit 0
    }

    # Load the rig setup file with the physical configuration
    log_msg "Loading DUT Setup File: $env(AUTO_RIGSETUP)"
    anvil loadsetup $env(AUTO_RIGSETUP)

    #Check if we meet the suite requirement.
    if ![anvil has $suite_requires] {

	log_msg "###########################################################################"
	log_msg "# Checking Suite Requires for $suite"
	log_msg "# Did not meet the test suite requirement \"${suite_requires}\", this test suite will not be run."	
	log_msg "###########################################################################\n"
	
	anvil cleanup pop -all
       
        if {[info exists env(RESULT_SCRIPT)] && ![info exists env(EMBTEST_SIM)]} {
	    set env(CASE_ID) "$embtest_anvil_case_id"
            log_msg "Inserting 'Not Run' result into database"
            if [catch {exec $env(RESULT_SCRIPT) -variant "\"$suite\": Requirements not met - $suite_requires" -result "Not Run"} errmsg] {
                log_msg "Result script execution return: $errmsg"
            }
        } else {
            if ![info exists env(RESULT_SCRIPT)] {
                log_msg "env(RESULT_SCRIPT) does not exist"
            }
            if [info exists env(EMBTEST_SIM)] {
                log_msg "Skipping creation of a result, embTest is being simulated"
            }
        }

	# Exit out of this instance of anvil
	puts stderr "\nEMBTESTOK\n\n"
	exit 0;

    } else {
	log_msg ""
	log_msg "###########################################################################"
	log_msg "# Checking Suite Requires for $suite"
	log_msg "# Satisfied suite requirement of \"${suite_requires}\""
	log_msg "###########################################################################\n"
	
    }
    
    set file_console_win "$env(EMBTEST_HOME)/tmp/win.$run_id"
	
    #Start a viewer, so we can see what's happening during boot time.
    log_msg "WIN: Launching boot viewer 1.."
    exec $env(EMBTEST_HOME)/console_window.pl -host [dut1.tsip] -port [dut1.tsport] -sdname [dut1.name] -file $file_console_win &

    # Load the rig setup file with the physical configuration
    log_msg "Loading Suite Setup File: ${stbdir}/scripts/${suite_setup}"
    if {$suite_setup != ""} {
        anvil loadsetup "${stbdir}/scripts/${suite_setup}"
    }
    log_msg ""

    log_msg "Loading DUT Config: ${stbdir}/scripts/${suite_config}"
    if {$suite_config != ""} {
       dut1 createconfig "${stbdir}/scripts/${suite_config}" -reboot
    }
    log_msg ""
        
    #Collect tshark capture for each subtest
    #Calling usage: (logs dir) (suite name)
    #Note: No parentheses

        set filter "ip net [[dut1.port1.network].prefix]/24 or ip net [[dut1.port2.network].prefix]/24 or"
    append filter " ip net [[dut1.port3.network].prefix]/24 or ip net [[dut1.port4.network].prefix]/24"

    #Don't append v6 filters if we're running USBC. Temporary until USBC v6 support is implemented. 5/31/12

    if ![anvil has old_usbc] {
        append filter " or ip6 net [[dut1.port1.network].ipv6_prefix]/64 or ip6 net [[dut1.port2.network].ipv6_prefix]/64 or"
        append filter " ip6 net [[dut1.port3.network].ipv6_prefix]/64 or ip6 net [[dut1.port4.network].ipv6_prefix]/64"
    }

    set run_cmd_tshark "$env(EMBTEST_HOME)/testshark.sh $stbdir/logs $suite '${filter}'"

    regsub -all {"} $run_cmd_tshark {\"} printable_run_cmd_tshark
    eval log_msg \"$printable_run_cmd_tshark\"

    if [catch {eval system $run_cmd_tshark} errmsg] {
        log_msg "Executing tshark capture return: $errmsg"
    }

    sleep 3

    if {$subtests == "{}"} {
        log_msg "Executing all available test cases for this suite"
        set q "SELECT DISTINCT case_name"
        append q " FROM test_case"
        append q " WHERE suite_id = '${suite_id}'"
        append q " ORDER BY case_name"
        set subtests [mysqlsel $db $q -flatlist]
    } else {
        log_msg "Executing select test cases for this suite"
        regsub -all {\{} $subtests "" subtests
        regsub -all {\}} $subtests "" subtests
        set subtests [regexp -all -inline {\S+} $subtests]
    }
    log_msg ""

    #Run ftp script to store the loaded config. NBT 
    set ftpconfigs_dir "$stbdir/logs/_ftp_configs"
    file mkdir $ftpconfigs_dir

    log_msg "Storing config to $ftpconfigs_dir"

    if { [catch {exec -ignorestderr $env(EMBTEST_HOME)/ftp_logs.pl -host [dut1.wancom0_ip] -dest $ftpconfigs_dir -save-config $suite}] } {
                    puts "Caught error - Something messed up with FTP script getting configs. Maybe."
    }


    #Kill console viewer 
    log_msg "WIN: Viewer - Removing $file_console_win"
    exec rm $file_console_win
    sleep 2

    log_msg "###########################################################################"
    log_msg "# Starting Test Case Execution for $suite"
    log_msg "###########################################################################"

    log_msg "Running $suite subtests: $subtests"
    foreach subtest $subtests {

        log_msg "Processing test case: $subtest"

        set q "SELECT case_id, script, requires, run_cmd_opts, visible"
        append q " FROM test_case"
        append q " WHERE case_name = '$subtest' AND suite_id = '$suite_id'"
        append q " LIMIT 1"
        mysqlsel $db $q

        mysqlmap $db {case_id script requires run_cmd_opts visible} {
            set case_id $case_id
            set case_script $script
            set case_requires $requires
            set case_run_cmd_opts $run_cmd_opts
            set case_visible $visible
            break;
        }

        # In order to simulate the same nomenclature of [dut1.tsport] for case information
        # create some tcl proc's
        proc case.id {} [list return $case_id]
        proc case.script {} [list return $case_script]
        proc case.requires {} [list return $case_requires]
        proc case.run_cmd_opts {} [list return $case_run_cmd_opts]
        proc case.visible {} [list return $case_visible]

        if {$case_visible == 0} {
            log_msg "Skipping $subtest, not visible"
            continue
        }

        set env(CASE_ID) "$case_id"

        # Check to make sure that we meet the test_case requirement
        if ![anvil has $case_requires] {
            log_msg "Did not meet the test case requirement \"${case_requires}\", this test case will not be run"

            if {[info exists env(RESULT_SCRIPT)] && ![info exists env(EMBTEST_SIM)]} {
                log_msg "Inserting 'Not Run' result into database"
                if [catch {exec $env(RESULT_SCRIPT) -variant "Case requirement not met: $case_requires" -result "Not Run"} errmsg] {
                    log_msg "Result script execution return: $errmsg"
                }
            } else {
                if ![info exists env(RESULT_SCRIPT)] {
                    log_msg "env(RESULT_SCRIPT) does not exist"
                }

                if [info exists env(EMBTEST_SIM)] {
                    log_msg "Skipping creation of a result, embTest is being simulated"
                }
            }
            continue
        } else {
            log_msg "Satisfied case requirement of \"${case_requires}\""
        }

        set start_time [clock seconds]
  
        set run_cmd "scripts/${suite_path}/${case_script} ${case_run_cmd_opts} >> $stbdir/logs/${suite}_${subtest}.log"
        # Remove all newline characters from $run_cmd
        regsub -all {[\n\r]+\s*} $run_cmd { } run_cmd

        # Make printable $run_cmd to print out to console
        regsub -all {"} $run_cmd {\"} printable_run_cmd
        eval log_msg \"$printable_run_cmd\"


        if ![info exists env(EMBTEST_SIM)] {
            log_msg "Executing test_case: $case_id"
            if [catch {eval exec $run_cmd} errmsg] {
                    log_msg "Test execution return: $errmsg"
            }
        } else {
            log_msg "Skipping executing test, embTest is being simulated"
        }
     
        set runtime [expr [clock seconds] - $start_time]

        if ![info exists env(EMBTEST_SIM)] {
            set q "UPDATE test_case SET runtime = '$runtime' WHERE case_id = '$case_id'"
            set retcode [mysqlexec $db $q]
            if {$retcode == 0} {
                log_msg "Unable to update test_case: $case_id with runtime $runtime"
            }
        } else {
            log_msg "Skipping updating case runtime, embTest is being simulated"
        }

        log_msg "Delaying 2 seconds..."
        log_msg ""
        sleep 2
    }
    
    #Kill PID of tshark
    #Command arguments: -suite -name -interface -dir

    set run_cmd_tsharkcleanup "$env(EMBTEST_HOME)/testsharkcleanup.pl -suite $suite -dir $stbdir/logs"

    regsub -all {"} $run_cmd_tsharkcleanup {\"} printable_run_cmd_tsharkcleanup
    eval log_msg \"$printable_run_cmd_tsharkcleanup\"

    if [catch {eval exec $run_cmd_tsharkcleanup} errmsg] {
    log_msg "Executing tshark cleanup return: $errmsg"
    }

    #Run script at the end of suite to collect logs.
    #Collects /ramdrv/ folder, npstats.dump, dump-etc-all.xz, and taskCheckDump.dat

    #set run_logcmd "$env(EMBTEST_HOME)/grab_logs.pl -host [dut1.tsip] -port [dut1.tsport] -sdname [dut1.name] -suitename $suite -logsdir logs -ftplogin user -ftppass acme -ftpip [dut1.wancom0_ip]"

    #regsub -all {"} $run_logcmd {\"} printable_run_logcmd
    #eval log_msg \"$printable_run_logcmd\"

    #if [catch {eval exec $run_logcmd} errmsg] {
    #    log_msg "Executing log acquisition return: $errmsg"
    #}

    # Clean up anything related to anvil that needs to be before exiting
    anvil cleanup pop -all

    if ![info exists env(EMBTEST_SIM)] {
        set env(CASE_ID) "$embtest_anvil_case_id"

        log_msg "Creating an embtest_anvil pass result"
        if [catch {exec $env(RESULT_SCRIPT) -variant "Test Suite \"$suite\" finished processing" -result "Pass"} msg] {
            log_msg "Result script execution return: $msg"
        }
    } else {
        log_msg "Skipping creation of embtest_anvil pass result, embTest is being simulated"
    }

    mysqlclose $db

    # Exit out of this instance of anvil
    puts stderr "\nEMBTESTOK\n\n"

    #set paramlist "logdir testbed_dir/logs "
    #append paramlist "nogui 1 "

    #set dis_console_mon [klget $raid_testinfo DISABLE_CONSOLE_MON]
    #if {[string compare $dis_console_mon "on"] != 0} {
    #    catch {exec $raid_dir/setups/consolemon.sh $crash_log}
    #}

    #set capture [klget $raid_testinfo CAPTURE]
    #if {[string compare $capture "on"] == 0} {
    #    catch {exec $raid_dir/setups/pcapture.sh}
    #}

} errmsg]} {
    log_msg "Caught error: $errmsg"
    #Kill console viewer 
    log_msg "WIN: Viewer - Caught error cleanup case - Removing $file_console_win"
    exec rm $file_console_win

    if ![info exists env(EMBTEST_SIM)] {
        set env(CASE_ID) "$embtest_anvil_case_id"

        log_msg "Creating an embtest_anvil fail result"
        if [catch {exec $env(RESULT_SCRIPT) -variant "embtest_anvil encountered an execution error during test suite \"$suite\", see log for details." -result "Fail"} msg] {
            log_msg "Result script execution return: $msg"
        }
    } else {
        log_msg "Skipping creation of embtest_anvil fail result, embTest is being simulated"
    }

    exit 1
}
