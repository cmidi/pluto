#!/usr/bin/perl

use Acme::embtestlib;
use Acme::Flow;
use Time::HiRes qw( usleep );
use Net::Telnet;
use Data::Dumper;
use POSIX qw(strftime);
use POSIX qw/ceil/;
use Getopt::Long;
use Errno;
use Switch;
use Cwd;

###################################################################################

#Untaint every input argument(ARGV) and every environmental variable (ENV).
#It is not secure, but we have to do it for now becasue anvil is run with setuid bit

&untaint_ARGV_ENV();

###################################################################################

my $returnVal = 0;
my $numSuccess = 0;
my $userpass = "acme";
my $enablepass = "packet";
my $vxworkspass = "vxworks";
 
my $tId= 0;
my $intf = 0;
my $match = "" ;
my $prematch = "" ;
my $prenat = 0;
 

my %recordingParameters = ( 'crs_id' => 1,
                            'crs_slot' => 0,
                            'crs_port' => 0,
                            'crs_vlan' => 10,
                       
			                'crs_sigip' => '2.2.2.2',
			                'crs_medip' => '2.2.2.2',
                            'crs_lip'  =>'2.2.2.1',	
			                'crs_dir'=>0);

my %sbcInfo = ('sdname' => "",
               'host'   => "",
               'port'   => 23 );

my %flowParameters = ( 'rsa' => '192.168.10.100',
                       'rda' => '192.168.10.2',
                       'rsp' => 6655,
                       'rdp' => 5566,
                       'rvlan' => 20,
                       'rslot' => 0,
                       'rport' => 1,
                       'lsa' => '172.16.0.200',
                       'lda' => '172.16.0.1',
                       'lsp' => 8877,
                       'ldp' => 7788,
                       'lvlan' => 10,
                       'lslot' => 1,
                       'lport' => 0);

GetOptions("host=s"       => \$sbcInfo{'host'},
            "port=i"       => \$sbcInfo{'port'},
            "sdname=s"     => \$sbcInfo{'sdname'},
            "crs_id=i"     => \$recordingParameters{'crs_id'},
            "crs_slot=i"   => \$recordingParameters{'crs_slot'},
            "crs_port=i"   => \$recordingParameters{'crs_port'},
            "crs_vlan=i"   => \$recordingParameters{'crs_vlan'},
            "crs_lip=s"      => \$recordingParameters{'crs_lip'},
			"crs_sigip=s"  => \$recordingParameters{'crs_sigip'},
			"crs_medip=s"  => \$recordingParameters{'crs_medip'},	
			"crs_dir=i"    =>  \$recordingParameters{'crs_dir'}
          );


sub die_handler
{
    system ( "$ENV{'RESULT_SCRIPT'} -variant 'none' -result 'Fail'" );
}

if(!defined($ENV{'RESULT_SCRIPT'}))
{
    $ENV{'RESULT_SCRIPT'} = "echo";
}
unless($sbcInfo{'host'})
{
    log_msg("Please specify a host(console server ip)");
    exit 1;
}

my @vlans = ();
my @slots = ();
my @ports = ();
my @ips =  (); 

my $session = Net::Telnet->new( Host => $sbcInfo{'host'}, Port => $sbcInfo{'port'} );
$session->input_log(*STDOUT);
if (!defined ($session))
{
	log_msg("Cannot connect to sd host $sbcInfo{'host'}: $!");
	exit 1;
}
log_msg("\nConnected to the console server. Starting script...");

if( sdGoToShellPrompt( Session => $session, Name => $sbcInfo{'sdname'} ) )
{
    log_msg("ERROR: Could not reach 'Password:' prompt.");
    exit 1;
}
else
{
    log_msg("Arrived at shell prompt");
}

for ($i=1;$i<=255;$i++)
{
      
    my @output = ();    
    my $range = 4000;
    my $slotportrange = 2;
    my $vlan = int(rand($range)); 
    my $slot = int(rand($slotportrange));
    my $port = int(rand($slotportrange));
    my @addr = qw (10 10 10 0 );
    my $temp = unpack("N",pack("C*",@addr));
    my $addr = int rand(2**32);
    my $addr2 = int(rand(2**32));
    $addr2 ^=$temp;
    $addr ^= $temp;
    my $ipaddr = join(".",unpack("C*",pack("N",$addr)));
    my $ipaddr2 = join(".",unpack("C*",pack("N",$addr2)));
    $session->print("");
    ($prematch, $match) = $session->waitfor(Match => "/->|acli-shell:/");
    @output = $session->cmd(String=>"test_crs_ext_mem_cmp "."$i,"."0,"."0,"."$vlan,"."\"$ipaddr\","."\"$ipaddr2\"",Timeout=>10,Prompt=>"/->|acli-shell:/");
    my $out = @output[0];    
    if(!($out =~ m/0x0$/i))
    {
        log_msg("TEST FAILED due to mem fail at location $i.");
        $numSuccess =1 ;
        exit 1;
        
            
    }
    else
    {
        log_msg("mem comapre pass for memory location $i");        
    }	
    
}
for ($j=1;$j<=255;$j++)
{
    $session->print ("");
    ($prematch, $match) = $session->waitfor(Match => "/->|acli-shell:/");
    @output =   $session->cmd(String =>"crs_remove "." $j",Timeout => 10,
                             Prompt => "/->|acli-shell:/" );
    log_msg("crs deleted with id $j");
}
if(!$numSuccess)
{
	log_msg("Test passed");
	system ( "$ENV{'RESULT_SCRIPT'} -variant 'none' -result 'Pass'" );
}
else
{
    log_msg("Test failed");
    system ( "$ENV{'RESULT_SCRIPT'} -variant 'none' -result 'Fail'" );
}
log_msg("Finished script, exiting...\n\n");

exit $returnVal;

# This is the last thing to be executed in the script before exiting
END
{
    # If we are returning something non-zero, insert a fail result
    # Note: This is mainly to protect against the script erroring out before creating a result
    if(($? != 0 || $returnVal != 0) && (defined($pid) && $pid != 0))
    {
        system ( "$ENV{'RESULT_SCRIPT'} -variant1 'none' -result 'Fail'" );
    }

}


 
