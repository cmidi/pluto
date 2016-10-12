#!/usr/bin/perl

use Getopt::Long;
use Cwd;

$suite = "";
#$testname = "";
#interface = "";
$dir = "";


#Commented out code for by test case capture. Script is for suite-based capture currently.

GetOptions( "suite=s"     => \$suite,
	   #"name=s"      => \$testname,
	   #"interface=s" => \$interface,
	    "dir=s"       => \$dir );

my($directory, $filename) = Cwd::abs_path($0) =~ m/(.*\/)(.*)$/;

#Untaint every input. It is not secure, but we have to do it for now becasue anvil is run with setuid bit
foreach (@ARGV)
{
    $_ =~ m/^(.*)$/ or die "Value is tainted\n";
    $_ = $1;
}
$ENV{"PATH"} = "";

#Untaint every ENV. It is not secure, but we have to do it for now becasue anvil is run with setuid bit
while(($key, $value) = each %ENV)
{
    $ENV{$key} =~ m/^(.*)$/ or die "Value is tainted\n";
    $ENV{$key} = $1;
}


#print("\nFile Name:   $suite\_$testname\_$interface\_pcap\.pid\n");
print("\nFile Name: $suite\_pcap\.pid\n");
print("Dir:         $dir\n" );

#open(PID, "$dir\/$suite\_$testname\_$interface\_pcap\.pid" ) or die $!;
open(PID, "$dir\/$suite\_pcap\.pid" ) or die $!;

my @pid = <PID>;
 
$PID = shift(@pid);

$PID =~ m/^(.*)$/ or die "Value is tainted\n";
$PID = $1;

print("Pid:         $PID\n");

system("$ENV{'EMBTEST_HOME'}/killtree.tcl $PID");

#$pidfile = "$dir\/$suite\_$testname\_$interface\_pcap\.pid";
$pidfile = "$dir\/$suite\_pcap\.pid";

$pidfile =~ m/^(.*)$/ or die "Value is tainted\n";
$pidfile = $1;

unlink($pidfile);

system("rm $pidfile");

print("Exiting tshark clean up script..\n");

exit 0;
