#!/usr/bin/expect
#
# Written by Scott McCulley

source raidlib.tcl
source database.tcl

if [catch {

    log_msg ""
    log_msg "####################################"
    log_msg "Starting Expected Result Filling!"
    log_msg "####################################"
    log_msg ""

    set limit [lindex $argv 0]
    set verbose [lindex $argv 1]
    set test_id_list {}

    set db [embtestdb_connect]

    set q "SELECT test_id FROM run ORDER BY start_time DESC LIMIT $limit"
    mysql::sel $db $q
    mysql::map $db {test_id} {
        lappend test_id_list $test_id
    }

    log_msg "test_id_list: "
    log_msg $test_id_list
    log_msg ""

    foreach test_id $test_id_list {
        set run_id ""
        set test_suite {}
      
        set q "SELECT run_id, test_suite"
        append q " FROM run"
        append q " WHERE test_id = '$test_id'"
      
        if {$verbose == 1} {
            log_msg "Query: $q"
        }
      
        mysql::sel $db $q
        mysql::map $db {run_id test_suite} {
            log_msg "run_id: $run_id"
            set test_suite [split $test_suite " "]
        }
      
        foreach val $test_suite {
            if {$verbose == 1} {
                log_msg ""
                log_msg "Filling in expected results for run_id: $run_id, test_suite: $val"
            }
            exec ./expected_result.tcl $run_id $val
        }

        if {$verbose == 1} {
            log_msg ""
            log_msg "Filling in expected results for run_id: $run_id, test_suite: EmbTest_Framework"
        }
        exec ./expected_result.tcl $run_id "EmbTest_Framework"
    }     

    log_msg ""
    log_msg "####################################"
    log_msg "Finished Expected Result Filling!"
    log_msg "####################################"
    log_msg ""

} errmsg] {
    puts "Error in expected_result: $errmsg"
    exit 1
}
