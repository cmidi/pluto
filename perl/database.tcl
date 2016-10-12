#!/usr/bin/expect

package require mysqltcl

set host "embtest"
set database "embtestdb"
set user "acme"
set password "abc123"

proc embtestdb_connect {} {
    set db [mysqlconnect -h "10.196.1.161" -u "acme" -password "abc123"]
    mysqluse $db embtestdb

    return $db
}

proc embtestdb_query {db q} {
    set retcode [mysqlexec $db $q]
    if {$retcode == 0} {
        error "Could not query database"
    }
}

proc embtestdb_close {db} {
    mysqlclose $db
}
