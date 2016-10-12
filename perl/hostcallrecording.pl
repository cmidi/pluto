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


$SIG{__DIE__} = \&die_handler;

# *** NOTE *** If wanting to connect via the console connection, precede the port # with 20

#########################
# Config (defaults)
my $returnVal = 1;
my $numSuccess = 0;
my $userpass = "acme";
my $enablepass = "packet";
my $vxworkspass = "vxworks";
my $cServerSet = 0; 
my $tId= 0;
my $intf = 0;
my $match = "" ;
my $prematch = "" ;

my %recordingParameters = ( 'crs_id' => 1,
                            'crs_slot' => 1,
                            'crs_port' => 0,
                            'crs_vlan' => 10,
                       
			                'crs_sigip' => '2.2.2.2',
			                'crs_medip' => '2.2.2.2',
                            'crs_mtu'  => 1480,
                            'crs_lip'  =>'2.2.2.1',	
			                'crs_dir'=>0);

my %flowParameters = ( 'rsa' => '172.16.0.200',
                       'rda' => '172.16.0.1',
                       'rsp' => 0,
                       'rdp' => 5068,
                       'rvlan' => 0,
                       'rslot' => 31,
                       'rport' => 0,
                       'lsa' => '0.0.0.0',
                       'lda' => '0.0.0.0',
                       'lsp' => 8877,
                       'ldp' => 7788,
                       'flow_mtu' => 1500,
                       'lvlan' => 10,
                       'lslot' => 0,
                       'lport' => 0);

my %listenerParameters = ('config' => "Listener_Config.txt",
                          'rpcap'  => "",
                          'rif'    => "eth2.20",
                          'lpcap'  => "",
                          'lif'    => "eth3.10",
			              'lttl '  => 128,
			              'ilttl'  => 128,
                          'crsigpcap'=> "",
                          'crpcap'  =>  "");

my %sbcInfo = ('sdname' => "",
               'host'   => "",
               'port'   => 23 );

my %packetParameters = ('size' => 256,
			            'type' => "udp",
                        'numpkts'=>1,
                         'fragment'=>0,
                         'fragmentsize'=>100); 

my $mtutest = 0;
GetOptions( "host=s"       => \$sbcInfo{'host'},
            "port=i"       => \$sbcInfo{'port'},
            "sdname=s"     => \$sbcInfo{'sdname'},

            "rsa=s"        => \$flowParameters{'rsa'},
            "rda=s"        => \$flowParameters{'rda'},
            "rsp=i"        => \$flowParameters{'rsp'},
            "rdp=i"        => \$flowParameters{'rdp'},
            "rvlan=i"      => \$flowParameters{'rvlan'},
            "rslot=i"      => \$flowParameters{'rslot'},
            "rport=i"      => \$flowParameters{'rport'},
            "rpcap=s"      => \$listenerParameters{'rpcap'},
            "rif=s"        => \$listenerParameters{'rif'},
            "lsa=s"        => \$flowParameters{'lsa'},
            "lda=s"        => \$flowParameters{'lda'},
            "lsp=i"        => \$flowParameters{'lsp'},
            "ldp=i"        => \$flowParameters{'ldp'},
            "lvlan=i"      => \$flowParameters{'lvlan'},
            "lslot=i"      => \$flowParameters{'lslot'},
            "lport=i"      => \$flowParameters{'lport'},
            "lpcap=s"      => \$listenerParameters{'lpcap'},
            "lif=s"        => \$listenerParameters{'lif'},
            "lif2=s"       => \$listenerParameters{'lif2'},
            "lttl=i"       => \$listenerParameters{'lttl'},
	        "ilttl=i"      => \$listenerParameters{'ilttl'},
            "crs_id=i"     => \$recordingParameters{'crs_id'},
            "crs_slot=i"   => \$recordingParameters{'crs_slot'},
            "crs_port=i"   => \$recordingParameters{'crs_port'},
            "crs_vlan=i"   => \$recordingParameters{'crs_vlan'},
            "crs_mtu=i"   => \$recordingParameters{'crs_mtu'},
            "crs_lip=s"      => \$recordingParameters{'crs_lip'},
			"crs_sigip=s"  => \$recordingParameters{'crs_sigip'},
			"crs_medip=s"  => \$recordingParameters{'crs_medip'},	
			"crs_dir=i"    =>  \$recordingParameters{'crs_dir'},
            "crpcap=s"       =>  \$listenerParameters{'crpcap'},
            "flow_mtu=i"  => \$flowParameters{'flow_mtu'},
            "crsigpcap=s"       =>  \$listenerParameters{'crsigpcap'},
            "mtutest=i"  => \$mtutest,
	   "psize=i"	      => \$packetParameters{'size'},
	   "ptype=s"	  => \$packetParameters{'type'},
        "pnum=i"      =>\$packetParameters{'numpkts'},
        "dofrag=i"    => \$packetParameters{'fragment'},
        "fragsize=i"  => \$packetParameters{'fragmentsize'});
##########################

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

if ($flowParameters{'lslot'}==0 && $flowParameters{'lport'}==0)
{
	$intf = 0;
}
elsif($flowParameters{'lslot'}==0 && $flowParameters{'lport'}==1)
{
    $intf = 2;

}
elsif($flowParameters{'lslot'}==1 && $flowParameters{'lport'}==0)
{
	$intf = 1;

}
else 
{
	$intf = 3;

}



my $session = Net::Telnet->new(Host => $sbcInfo{'host'}, Port => $sbcInfo{'port'});
$session->input_log( *STDOUT );
if(!defined($session))
{
    log_msg("Can't connect to SD HOST $sbcInfo{'host'}: $!");
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
    log_msg("Arrived at password prompt");
}
log_msg("entered shell");
$session->print ("");
($prematch, $match) = $session->waitfor(Match => "/->|acli-shell:/");
@output =   $session->cmd(String =>"test_crs_add "." $recordingParameters{'crs_id'},"."$recordingParameters{'crs_slot'},"."$recordingParameters{'crs_port'},"."$recordingParameters{'crs_vlan'},"."\"$recordingParameters{'crs_sigip'}\","."\"$recordingParameters{'crs_medip'}\"",Timeout => 10,
                             Prompt => "/->|acli-shell:/" );
my $out = @output[0];
if(!($out =~ m/0x0$/i))
{
        log_msg("TEST FAILED due to call recording server not being set.");
        $numSuccess =1 ;
        
}
else
{
        log_msg("recorder server added with output:$out");
}	
if($mtutest)
{
    log_msg("Arrived at MTU test");    
    $session->print("");
    ($prematch,$match)= $session->waitfor(Match =>"/->|acli-shell:/");
    $session->print("nPApp_Media_set_mtu_net_intf "."$flowParameters{'lslot'},"."$flowParameters{'lport'},"."$flowParameters{'lvlan'},"."$flowParameters{'flow_mtu'}");
    ($prematch,$match)= $session->waitfor(Match =>"/->|acli-shell:/");
    $session->print("nPApp_Media_set_mtu_net_intf "."$recordingParameters{'crs_slot'},"."$recordingParameters{'crs_port'},"."$recordingParameters{'crs_vlan'},"."$recordingParameters{'crs_mtu'}");
    ($prematch,$match)= $session->waitfor(Match =>"/->|acli-shell:/");
}
my $flow = Acme::Flow->new(Session => $session, Name => $sbcInfo{'sdname'});
if(!defined($flow))
{
    log_msg("Can't create Flow object: $!");
    exit 1;
}

$flow->ppxFlowCreate();
log_msg("Current ppxFlowID: " . $flow->getPpxFlowID());

$flow->ppxFlowAddFeatureNat(sa       => $flowParameters{'rsa'},
                            da       => $flowParameters{'rda'},
                            sp       => $flowParameters{'rsp'},
                            dp       => $flowParameters{'rdp'},
                            xsa      => $flowParameters{'lsa'},
                            xda      => $flowParameters{'lda'},
                            xsp      => $flowParameters{'ldp'},
                            xdp      => $flowParameters{'ldp'},
                            igr_slot => $flowParameters{'rslot'},
                            igr_port => $flowParameters{'rport'},
                            igr_vlan => $flowParameters{'rvlan'},
                            egr_slot => $flowParameters{'lslot'},
                            egr_port => $flowParameters{'lport'},
                            egr_vlan => $flowParameters{'lvlan'});
#
#$flow->ppxFlowAddFeatureCrs(crs_id =>$recordingParameters{'crs_id'},
 #                           crs_dir=>$recordingParameters{'crs_dir'});
#

if($flow->ppxFlowApply() != 0)
{
    log_msg("Could not create static flow, exiting...");
    exit 1;
}

log_msg("FG Index: " . $flow->getFgIndex());
my @pids;
if($listenerParameters{'crpcap'} ne "")
{
	
    $pid = fork();
	if($pid)
    {
        #parent
        log_msg("Forking for $config, pid is $pid, parent $$");
        push(@pids, $pid); 
        log_msg("Pids: @pids"); 
        
    }
	elsif($pid == 0)
	{
        	
            $command = "sd_listener --lsa $recordingParameters{'crs_lip'}".
				          " --lda $recordingParameters{'crs_medip'}".
				          " --ilsa $flowParameters{'lsa'}" .
	                      " --ilda $flowParameters{'lda'}" .
	                      " --ilsp $flowParameters{'lsp'}" .
	                      " --ildp $flowParameters{'ldp'}" .
				          " --lttl $listenerParameters{'lttl'}".
				          " --ilttl $listenerParameters{'ilttl'}".
			              " --lif $listenerParameters{'lif'}" .
	                      " --lpc $listenerParameters{'crpcap'}".
	                      " --tmo 15";
        log_msg ("$command","CHILD");
            my @results = `$command`;
            
            log_msg("SD_Listener Results:\n@results", "CHILD");  
            @results = trimArray( @results );
            
	    if(!(grep $_ =~ /success/i, @results))
	    {
    	    log_msg("Failed to recieve expected packets. ", "CHILD");
		    exit(1);
	    }
	    else 
	    {   
		    log_msg("expected packets recieved", "CHILD");			
		    log_msg ("what is $$");
		    exit(0);
		
	    }
    }
}
if($listenerParameters{'crsigpcap'} ne "")
{
	
    $pid = fork();
	if($pid)
    {
        #parent
        log_msg("Forking for $config, pid is $pid, parent $$");
        push(@pids, $pid); 
        log_msg("Pids: @pids"); 
        
    }
	elsif($pid == 0)
	{
            $command = "sd_listener --lsa $recordingParameters{'crs_lip'}".
				          " --lda $recordingParameters{'crs_sigip'}".
				          " --ilsa $flowParameters{'lsa'}" .
	                      " --ilda $flowParameters{'lda'}" .
	                      " --ilsp $flowParameters{'lsp'}" .
	                      " --ildp $flowParameters{'ldp'}" .
				          " --lttl $listenerParameters{'lttl'}".
				          " --ilttl $listenerParameters{'ilttl'}".
			              " --lif $listenerParameters{'lif'}" .
	                      " --lpc $listenerParameters{'crsigpcap'}".
	                      " --tmo 15";
        
        log_msg ("$command","CHILD");
            my @results = `$command`;
            
            log_msg("SD_Listener Results:\n@results", "CHILD");  
            @results = trimArray( @results );
            
	    if(!(grep $_ =~ /success/i, @results))
	    {
    	    log_msg("Failed to recieve expected packets. ", "CHILD");
		    exit(1);
	    }
	    else 
	    {   
		    log_msg("expected packets recieved", "CHILD");			
		    log_msg ("what is $$");
		    exit(0);
		
	    }
    }
}
$session->print("");

($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
$session->print("shellSendPktClear");
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
$session->print("shellSendPktCfg "."\"srcip,destip\"," .
                                             "\"$flowParameters{'lsa'}\"," .
                                             "\"$flowParameters{'lda'}\"" );
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
$session->print("shellSendPktCfg "."\"srcport,destport,vlan,interface,numpkts,payloadsize,debug,proto\", " ."$flowParameters{'lsp'},"."$flowParameters{'ldp'},"."$flowParameters{'lvlan'},"."$intf,"."1,"."$packetParameters{'size'},"."0,"."\"$packetParameters{'type'}\"");
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
$session->print("shellSendPktCfg "."\"dofrag\"," ."$packetParameters{'fragment'}");
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
if($packetParameters{'fragment'})
{
    $session->print("shellSendPktCfg "."\"fragmentsize\","."$packetParameters{'fragmentsize'}");
    ($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
}
$session->print("shellSendPktCfg "."\"crsid\","."$recordingParameters{'crs_id'}");
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
$session->print("shellSendPktCfg "."\"fwdcode\","."0x04");
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
$session->print("shellSendPkt");
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );

foreach (@pids)
{
    my $tmp = waitpid($_,0);		
	$? = $? >> 8;	
	log_msg("Child $tmp finished with result $?");	
	$numSuccess += $?;
	log_msg ("$numSuccess");
	
}
if(!defined($flow->ppxFlowDestroy()))
{
    log_msg("Could not destroy static flow, exiting...");
    exit 1;
}
$session->print ("");
($prematch, $match) = $session->waitfor(Match => "/->|acli-shell:/");
@output =   $session->cmd(String =>"crs_remove "." $recordingParameters{'crs_id'}",Timeout => 10,
                             Prompt => "/->|acli-shell:/" );

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




log_msg("Script finished, exiting...");
$returnVal = 0;

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










