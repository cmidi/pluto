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

my $returnVal  = 1;
my $hifn       = 0;
my $variant    = "DIE HANDLER";
my $parent_pid = $$;

my %recordingParameters = ( 'crs_id'    => 1,
                            'crs_slot'  => 0,
                            'crs_port'  => 0,
                            'crs_vlan'  => 10,
                       
                            'crs_sigip' => '2.2.2.2',
                            'crs_medip' => '2.2.2.2',
                            'crs_lip'   => '2.2.2.1',	
                            'crs_dir'   => 0 );

my %listenerParameters = ('config'    => "Listener_Config.txt",
                          'rpcap'     => "",
                          'rif'       => "eth2",
                          'lpcap'     => "",
                          'lpcap2'    => "",
                          'lif2'      => "eth2",
                          'lif'       => "eth2",
                          'lttl '     => 128,
                          'ilttl'     => 128,
                          'crsigpcap' => "",
                          'crpcap'    => "",
                          'crpcap2'   => "");

my %sbcInfo = ('sdname' => "",
               'host'   => "",
               'port'   => 23 );

my %flowParameters = ( 'rsa'   => '192.168.10.100',
                       'rda'   => '192.168.10.2',
                       'rsp'   => 6655,
                       'rdp'   => 5566,
                       'rvlan' => 20,
                       'rslot' => 0,
                       'rport' => 1,
                       'lsa'   => '172.16.0.200',
                       'lda'   => '172.16.0.1',
                       'lsp'   => 8877,
                       'ldp'   => 7788,
                       'lvlan' => 10,
                       'lslot' => 1,
                       'lport' => 0);

my %packetParameters = ( 'size' => 256,
                         'type' => 0 ); #type defines type of packet SUDP,RTPUDP,SIP,TCP if possible to create all these 0 = UDP
my $debug = 0;

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
            "lpcap2=s"     => \$listenerParameters{'lpcap2'},
            "lif=s"        => \$listenerParameters{'lif'},
            "lif2=s"       => \$listenerParameters{'lif2'},
            "lttl=i"       => \$listenerParameters{'lttl'},
            "ilttl=i"      => \$listenerParameters{'ilttl'},
            "crs_id=i"     => \$recordingParameters{'crs_id'},
            "crs_slot=i"   => \$recordingParameters{'crs_slot'},
            "crs_port=i"   => \$recordingParameters{'crs_port'},
            "crs_vlan=i"   => \$recordingParameters{'crs_vlan'},
            "crs_lip=s"    => \$recordingParameters{'crs_lip'},
            "crs_sigip=s"  => \$recordingParameters{'crs_sigip'},
            "crs_medip=s"  => \$recordingParameters{'crs_medip'},	
            "crs_dir=i"    => \$recordingParameters{'crs_dir'},
            "crpcap=s"     => \$listenerParameters{'crpcap'},
            "crpcap2=s"    => \$listenerParameters{'crpcap2'},
            "crsigpcap=s"  => \$listenerParameters{'crsigpcap'},      
            "debug=i"      => \$debug,
            "hifn=i"       => \$hifn );

##########################

if(!defined($ENV{'RESULT_SCRIPT'}))
{
    $ENV{'RESULT_SCRIPT'} = "echo";
}

unless($sbcInfo{'host'})
{
    log_msg("Please specify a host(console server ip)");
    $variant = "Invalid host";
    exit 1;
}
my $session = Net::Telnet->new( Host => $sbcInfo{'host'}, Port => $sbcInfo{'port'} );
$session->input_log(*STDOUT);

if( sdGoToShellPrompt( Session => $session, Name => $sbcInfo{'sdname'} ) )
{
    log_msg("ERROR: Could not reach 'Password:' prompt.");
    $variant = "Unable to reach shell prompt";
    exit 1;
}

log_msg("\nConnected to the console server. Starting script...");

$session->print ("");
($prematch, $match) = $session->waitfor(Match => "/->|acli-shell:/");
@output =   $session->cmd(String =>"test_crs_add "." $recordingParameters{'crs_id'},"."$recordingParameters{'crs_slot'},"."$recordingParameters{'crs_port'},"."$recordingParameters{'crs_vlan'},"."\"$recordingParameters{'crs_sigip'}\","."\"$recordingParameters{'crs_medip'}\"",Timeout => 10,
                             Prompt => "/->|acli-shell:/" );
my $out = @output[0];
if(!($out =~ m/0x0$/i))
{
    log_msg("TEST FAILED due to call recording server not being set.");
    $variant = "Failed to set call recording server";
    exit 1;
}
else
{
    log_msg("trace added with output:$out");       
}

if($debug)
{
    log_msg("Debug is on reset frag dump stats");
    $session->print("");
    ($prematch, $match) = $session->waitfor(Match => "/->|acli-shell:/");
    $session->print("IPF_reset_stats6");
    ($prematch, $match) = $session->waitfor(Match => "/->|acli-shell:/");
}

my $flow = Acme::Flow->new(Session => $session, Name => $sbcInfo{'sdname'});
if(!defined($flow))
{
    log_msg("Can't create Flow object: $!");
    $variant = "Unable to connect to flow module";
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
                            xsp      => $flowParameters{'lsp'},
                            xdp      => $flowParameters{'ldp'},
                            igr_slot => $flowParameters{'rslot'},
                            igr_port => $flowParameters{'rport'},
                            igr_vlan => $flowParameters{'rvlan'},
                            egr_slot => $flowParameters{'lslot'},
                            egr_port => $flowParameters{'lport'},
                            egr_vlan => $flowParameters{'lvlan'});

$flow->ppxFlowAddFeatureCrs(crs_id =>$recordingParameters{'crs_id'},
                            crs_dir=>$recordingParameters{'crs_dir'});

if($flow->ppxFlowApply() != 0)
{
    log_msg("Could not create static flow, exiting...");
    $variant = "Unable to create static flow";
    exit 1;
}

log_msg("FG Index: " . $flow->getFgIndex());

################# RUN SD_LISTENER #####################
my $command = "";
my $results = "";
my $crpcap  = $hifn ? $listenerParameters{'crpcap2'} : $listenerParameters{'crpcap'};
my $lpcap   = $hifn ? $listenerParameters{'lpcap2'} : $listenerParameters{'lpcap'};

#Run SD Listener and return its result
if($crpcap ne "")
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
        if ($recordingParameters{'crs_dir'} == 1)   
        {
            $command = "sd_listener --lsa $recordingParameters{'crs_lip'}".
                                  " --lda $recordingParameters{'crs_medip'}".
                                  " --ilsa $flowParameters{'lsa'}" .
                                  " --ilda $flowParameters{'lda'}" .
                                  " --ilsp $flowParameters{'lsp'}" .
                                  " --ildp $flowParameters{'ldp'}" .
                                  " --lttl $listenerParameters{'lttl'}".
                                  " --ilttl $listenerParameters{'ilttl'}".
                                  " --lif $listenerParameters{'lif2'}" .
                                  " --lpc $crpcap".
                                  " --tmo 15";
        }
        else 
        {

            $command = "sd_listener --lsa $recordingParameters{'crs_lip'}".
                                  " --lda $recordingParameters{'crs_medip'}".
                                  " --ilsa $flowParameters{'rsa'}" .
                                  " --ilda $flowParameters{'rda'}" .
                                  " --ilsp $flowParameters{'rsp'}" .
                                  " --ildp $flowParameters{'rdp'}" .
                                  " --lttl $listenerParameters{'lttl'}".
                                  " --ilttl $listenerParameters{'ilttl'}".
                                  " --lif $listenerParameters{'lif2'}" .
                                  " --lpc $crpcap" .
                                  " --tmo 15"; 
        }
        log_msg ("$command","CHILD");
        @results = `$command`;
            
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
        if ($recordingParameters{'crs_dir'} == 1)   
        {
            $command = "sd_listener --lsa $recordingParameters{'crs_lip'}".
                                  " --lda $recordingParameters{'crs_sigip'}".
                                  " --ilsa $flowParameters{'lsa'}" .
                                  " --ilda $flowParameters{'lda'}" .
                                  " --ilsp $flowParameters{'lsp'}" .
                                  " --ildp $flowParameters{'ldp'}" .
                                  " --lttl $listenerParameters{'lttl'}".
                                  " --ilttl $listenerParameters{'ilttl'}".
                                  " --lif $listenerParameters{'lif2'}" .
                                  " --lpc $listenerParameters{'crsigpcap'}".
                                  " --tmo 15";
        }
        else 
        {

            $command = "sd_listener --lsa $recordingParameters{'crs_lip'}".
                                  " --lda $recordingParameters{'crs_sigip'}".
                                  " --ilsa $flowParameters{'rsa'}" .
                                  " --ilda $flowParameters{'rda'}" .
                                  " --ilsp $flowParameters{'rsp'}" .
                                  " --ildp $flowParameters{'rdp'}" .
                                  " --lttl $listenerParameters{'lttl'}".
                                  " --ilttl $listenerParameters{'ilttl'}".
                                  " --lif $listenerParameters{'lif2'}" .
                                  " --lpc $listenerParameters{'crsigpcap'}" .
                                  " --tmo 15";  
        }
        log_msg ("$command","CHILD");
        @results = `$command`;
            
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
sleep(1);
$command = "sd_listener --rsa $flowParameters{'rsa'}" .
                      " --rda $flowParameters{'rda'}" .
                      " --rsp $flowParameters{'rsp'}" .
                      " --rdp $flowParameters{'rdp'}" .
                      " --rif $listenerParameters{'rif'}" .
                      " --rpc $listenerParameters{'rpcap'}" .
                      " --lsa $flowParameters{'lsa'}" .
                      " --lda $flowParameters{'lda'}" .
                      " --lsp $flowParameters{'lsp'}" .
                      " --ldp $flowParameters{'ldp'}" .
                      " --lif $listenerParameters{'lif'}" .
                      " --lpc $lpcap" .
                      " --tmo 15";

log_msg("Executing: $command\n");
@results = `$command`;
log_msg("SD_Listener Results:\n@results");
@results = trimArray( @results );


###returning Results####
my $childrenResults = 0;
if( grep $_ =~ /success/i, @results ) 
{
    foreach(@pids)
    {
        log_msg("Child pid $_");

        my $tmp = waitpid($_, 0);
        $? = $? >> 8;
        log_msg("Child $tmp finished with result $?");
        $childrenResults += $?;
    }
    
    if($childrenResults == 0)
    {
        $returnVal = 0;
    }
    else
    {
        log_msg("Spawned Children failed to recieve expected packets.  " );
    }
    
}
else
{
    log_msg("Parent failed to receive expected packets. ");
}

############### SD LISTENER FINISH! ###################
if(!defined($flow->ppxFlowDestroy()))
{
    log_msg("Could not destroy static flow, exiting...");
    $variant = "Unable to destroy flow";
    exit 1;
}
$session->print ("");
($prematch, $match) = $session->waitfor(Match => "/->|acli-shell:/");
@output =   $session->cmd(String =>"crs_remove "." $recordingParameters{'crs_id'}",Timeout => 10,
                             Prompt => "/->|acli-shell:/" );
if($debug)
{
    log_msg("Debug is on print frag dump stats");
    $session->print("");
    ($prematch, $match) = $session->waitfor(Match => "/->|acli-shell:/");
    $session->print("IPF_dump_stats6");
    ($prematch, $match) = $session->waitfor(Match => "/->|acli-shell:/");
}
if($returnVal == 0)
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

sleep( 1 );

exit 0;

# This is the last thing to be executed in the script before exiting
END
{
    #Insert fail result if parent exits abnormally.
    if($parent_pid == $$ && $? != 0)
    {
        system ( "$ENV{'RESULT_SCRIPT'} -variant '$variant' -result 'Fail'" );
    }
}

