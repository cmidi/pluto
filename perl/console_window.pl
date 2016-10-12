#!/usr/bin/perl

#Script to view what bootup is doing during anvil stuff.

use Acme::embtestlib;
use Acme::Flow;
use Time::HiRes qw( usleep );
use Net::Telnet;
use Data::Dumper;
use POSIX qw(strftime);
use POSIX qw/ceil/;
use Getopt::Long;
use Errno;
use Cwd;

my($directory, $filename) = Cwd::abs_path($0) =~ m/(.*\/)(.*)$/;

###################################################################################

#Untaint every input argument(ARGV) and every environmental variable (ENV).
#It is not secure, but we have to do it for now becasue anvil is run with setuid bit

&untaint_ARGV_ENV();

###################################################################################

$file="";

%sbcInfo   = (  'sdname'    => "",
                'host'      => "",
                'port'      => 23 );


GetOptions(     "host=s"     => \$sbcInfo{'host'},
                "port=i"     => \$sbcInfo{'port'},
                "sdname=s"   => \$sbcInfo{'sdname'},
                "file=s"     => \$file);

#Verify input.
unless($sbcInfo{'host'} && $sbcInfo{'sdname'} && $sbcInfo{'port'} && $file)
{
    log_msg("EMB: Error: Specify Terminal Server IP using -host x.x.x.x and port using -port (20xx/30xx/100xx) and the system name using -sdname somename.");
    log_msg("EMB: Error: Specify filename to check for script to terminate on with -file");
    exit 1;
}

#To start, make the file of which we will be checking the existence.
system("touch $file");

#Set up connection to TS.
my $session = Net::Telnet->new(Host => $sbcInfo{'host'}, Port => $sbcInfo{'port'});
$session->input_log( *STDOUT );

$count = 0;

#If count reaches 900 exit, if file is removed, exit.
while( -e $file) {
    if($count >= 900){
        log_msg("EMB: Count is > 900. Remove file and exit: $file");
        system("rm $file");
        $session->close;
        exit 0;
    }
    ( $prematch, $match ) = $session->waitfor( Match   => "/somethingsomethingderp/",
                                               Timeout => 1,
                                               Errmode => "return" );

    $count++;
}

#File has been removed. Exit
$session->close;
log_msg("EMB: $file has been removed, exiting.");
exit 0;

