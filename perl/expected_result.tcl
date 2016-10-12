#!/usr/bin/expect
#
# Written by Scott McCulley

source raidlib.tcl
source database.tcl

set MAX_LIST_SIZE 20

if [catch {

    log_msg ""
    log_msg "####################################"
    log_msg "Starting Expected Result Processing!"
    log_msg "####################################"
    log_msg ""

    set run_id [lindex $argv 0]
    set test_suite_name  [lindex $argv 1]

    set suite_success 0
    set test_suite_id ""
    set suite_selection_id "" 
    set image_version ""
    set testbed "" 
    set current_pass_cnt ""
    set current_fail_cnt ""
    set top_pass_cnt 0
    set pass_cnt_list ""
    set bottom_fail_cnt 0
    set fail_cnt_list ""

    set db [embtestdb_connect]

    set q "SELECT suite_selection_id, image_version, testbed"
    append q " FROM run"
    append q " WHERE run_id = '$run_id'"
    append q " LIMIT 1"

    log_msg "Query: $q"

    mysql::sel $db $q
    mysql::map $db {suite_selection_id image_version testbed} {
        set image_version [lrange [regexp -inline -all -- {[a-zA-Z]+[0-9]\S+} $image_version] 0 0]
    }

    set q "SELECT suite_id FROM test_suite WHERE suite_name = '$test_suite_name' LIMIT 1"
    mysql::sel $db $q
    mysql::map $db {test_suite_id} {}

    log_msg "run_id:             $run_id"
    log_msg "suite_selection_id: $suite_selection_id"
    log_msg "test_suite_id:      $test_suite_id"
    log_msg "image_version:      $image_version"
    log_msg "test_bed:           $testbed"
    log_msg ""

    set q "SELECT SUM(IF(result = 'Pass', 1, 0)) as current_pass_cnt"
    append q " FROM result"
    append q " WHERE (SELECT test_case.suite_id FROM test_case WHERE test_case.case_id = result.case_id) = $test_suite_id"
    append q " AND result.run_id = '$run_id'"

    log_msg "Query: $q"

    set current_pass_cnt 0

    mysql::sel $db $q
    mysql::map $db {current_pass_cnt} {}

    if {$current_pass_cnt < 1} {
        set current_pass_cnt 0
    }
    log_msg "current_pass_cnt: $current_pass_cnt"

    set q "SELECT top_pass_cnt"
    append q " FROM expected_results"
    append q " WHERE suite_selection_id = '$suite_selection_id'"
    append q " AND test_suite_id = '$test_suite_id'"
    append q " AND image_version = '$image_version'"
    append q " AND testbed = '$testbed'" 
    append q " LIMIT 1"

    #log_msg "Query: $q"

    set top_pass_count 0

    mysql::sel $db $q
    mysql::map $db {top_pass_cnt} {}
    if {$top_pass_cnt < 1} {
        set top_pass_cnt 0
    }

    log_msg "top_pass_cnt: $top_pass_cnt"
    log_msg "current_pass_cnt: $current_pass_cnt"

    set dumbness [expr $top_pass_cnt < $current_pass_cnt]
    if {$dumbness} {
        log_msg "Updating top_pass_cnt($top_pass_cnt) to $current_pass_cnt"
        log_msg ""
        set top_pass_cnt $current_pass_cnt
    }

    log_msg "Updated top_pass_cnt = $top_pass_cnt"
    log_msg ""

    set q "INSERT INTO expected_results (suite_selection_id, test_suite_id"
    append q ", image_version, testbed, top_pass_cnt)"
    append q " VALUES ('$suite_selection_id', '$test_suite_id'"
    append q ", '$image_version', '$testbed', '$top_pass_cnt')"
    append q " ON DUPLICATE KEY UPDATE"
    append q " top_pass_cnt = '$top_pass_cnt'"

    log_msg "Query: $q"

    mysql::sel $db $q

    mysqlclose $db

    log_msg "####################################"
    log_msg "Finished Expected Result Processing!"
    log_msg "####################################"
    log_msg ""

} errmsg] {
    puts "Error in expected_result: $errmsg"
    exit 1
}

