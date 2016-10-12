#!/usr/bin/perl

# SLB mode check script - Meng Wang

use Acme::embtestlib;
use Net::Telnet;
use Getopt::Long;

###################################################################################

#Untaint every input argument(ARGV) and every environmental variable (ENV).
#It is not secure, but we have to do it for now becasue anvil is run with setuid bit

&untaint_ARGV_ENV();

###################################################################################

# *** NOTE *** If wanting to connect via the console connection, precede the port # with 20

%sbcInfo = (  'sdname'    => "",
              'host'      => "",
              'port'      => 23 );

$suite = "";

GetOptions( "host=s"     => \$sbcInfo{'host'},
            "port=i"     => \$sbcInfo{'port'},
            "sdname=s"   => \$sbcInfo{'sdname'},
            "suite=s"    => \$suite );

if(!defined($ENV{'RESULT_SCRIPT'}))
{
    $ENV{'RESULT_SCRIPT'} = "echo";
}

unless($sbcInfo{'host'})
{
    log_msg("Please specify a host(console server ip)");
    exit 0;
}

#Set up the telnet session.
my $session = Net::Telnet->new(Host => $sbcInfo{'host'}, Port => $sbcInfo{'port'});

$session->input_log( *STDOUT );

if(sdGoToLinuxPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
{
    log_msg("ERROR: Could not reach '~ #' prompt.");
    exit 0;
}

# create slb file under /boot when in SLB suite, otherwise remove slb file
if($suite eq "SLB_Test")
{
    log_msg("enable SLB mode.\n");
    $session->print("echo 'slb mode' > /boot/slb_boot");
}
else
{
    log_msg("disable SLB mode.\n");
    $session->print("rm /boot/slb_boot");
}
($prematch, $match) = $session->waitfor(String => "#",Timeout => 10);

$session->close;

log_msg("----Finished setting slb mode..");
log_msg("----Exiting.");

exit 0;

