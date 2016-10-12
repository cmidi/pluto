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

sub captureRecServer
{
    my $telnet     = "";
    my %parameters = ();
    my $error      = -1;
    my $serverSet  = 1;
    my $match      = "" ;
    my $prematch   = "" ;
    my $serverType = 0;
    
    #check arguments
    if(@_ > 0 && (@_ % 2) == 0) 
    {
        while(($_,$argument)= splice(@_,0,2))
        {
            if(/^-?telnet$/i)
            {
                $telnet = $argument;                    
            }       
            elsif (/^-?parameters$/i)
            {
                %parameters = %{$argument};                     
            }
            
            elsif(/^-?stype/i)
            {
                $serverType = $argument;                                
            }       
        }                                       
    }
    
    $telnet ->print ("");
    ($prematch, $match) = $telnet->waitfor(Match => "/->|acli-shell:/");
    
    # create a packet trace server 
    $telnet->print("npapp_trace_enable". " 1");
    ($prematch,$match) = $telnet->waitfor(Match => "/->|acli-shell:/" );
    
    
    $telnet->print("test_npapp_trace_add_server "."\"$parameters{'cl_ip'}\","." \"$parameters{'cs_ip'}\","."$parameters{'cvlan'},"."$parameters{'cslot'},"."$parameters{'cport'}");
    ($prematch,$match) = $telnet->waitfor(Match => "/->|acli-shell:/");
    return $serverSet;
}


sub captureRecActivate
{       
    my $telnet     = "";
    my %parameters = ();
    my $traceStart = 0;
    my $match      = "" ;
    my $prematch   = "" ;
    my $traceId    = 0;
    my @output     = ();
    my @output2    = ();
    my $tracenumber;
    
    #check arguments 
    if (@_ > 0 && (@_ % 2) == 0) # changes in argument type can add type of trace in arguments such as trace at end point or net intf
        {
            while(($_,$argument)= splice(@_,0,2))
            {
                if(/^-?telnet$/i)
                {
                    $telnet = $argument;                    
                }       
                elsif (/^-?parameters$/i)
                {
                    %parameters = %{$argument};                     
                }
                elsif(/^-?tracenumber$/i)
                {
                    $tracenumber = $argument;
                }                   
                
                
            }       
        }
    
    my @fakeTraces=("1.1.1.1",
                    "3.3.3.3",
                    "4.3.2.1",
                    "1.2.3.4",
                    "4.4.4.4",
                    "5.5.5.5",
                    "6.6.6.6",
                    "7.7.7.7",
                    "8.8.8.8",
                    "9.9.9.9",
                    "10.10.10.10",
                    "11.11.11.11",
                    "12.12.12.12",
                    "14.14.14.14",
                    "13.13.13.13");
   
    log_msg("configuring packet trace");
    $telnet->print("");
    ($prematch,$match) = $telnet->waitfor(Match => "/->|acli-shell:/");
    
    if($tracenumber==1)
    {       
        @output =   $telnet->cmd(String =>"test_npapp_trace_activate "." $parameters{'tslot'},"."$parameters{'tport'},"."$parameters{'tvlan'},"."\"$parameters{'tip_add'}\","."$parameters{'tlport'},"."$parameters{'trport'},"."$parameters{'mode'}",Timeout => 10,
                                 Prompt => "/->|acli-shell:/" );
        my $out = @output[0];
        if(!($out =~ m/0x0$/i))
        {
            log_msg("trace not added with output:$out");
            $traceId = 0; 
        }
        else
        {
            log_msg("trace added with output:$out");    
            $traceId = $traceId + 1 ;
            
        }   
    }
    
    elsif($tracenumber==2)
    {
        @output =   $telnet->cmd(String =>"test_npapp_trace_activate "." $parameters{'rslot'},"."$parameters{'rport'},"."$parameters{'rvlan'},"."\"$parameters{'tip_add'}\","."$parameters{'tlport'},"."$parameters{'trport'},"."$parameters{'mode'}",Timeout => 10,
                                 Prompt => "/->|acli-shell:/" );
        my $out = @output[0];
        if(!($out =~ m/0x0$/i))
        {
            log_msg("trace not added with output:$out");
            $traceId = 0; 
        }
        else
        {
            log_msg("trace added with output:$out");    
            $traceId = $traceId + 1 ;
            
        }       
        
        @output2 =   $telnet->cmd(String =>"test_npapp_trace_activate "." $parameters{'lslot'},"."$parameters{'lport'},"."$parameters{'lvlan'},"."\"$parameters{'tip_add2'}\","."$parameters{'tlport'},"."$parameters{'trport'},"."$parameters{'mode'}",Timeout => 10,
                                  Prompt => "/->|acli-shell:/" );
        my $out2 = @output2[0];
        if(!($out2 =~ m/0x0$/i))
        {
            log_msg("trace not added with output:$out");
            $traceId = 0; 
        }
        else
        {
            log_msg("trace added with output:$out");    
            $traceId = $traceId + 1 ;
            
        }   
        
        
        
    }
    elsif($tracenumber==16)
    {
        
        for ($i=0;$i<=14;$i++)
        {
            @output =   $telnet->cmd(String =>"test_npapp_trace_activate "." $parameters{'rslot'},"."$parameters{'rport'},"."$parameters{'rvlan'},"."\"$fakeTraces[$i]\","."$parameters{'tlport'},"."$parameters{'trport'},"."$parameters{'mode'}",Timeout => 10,
                                     Prompt => "/->|acli-shell:/" );
            my $out = @output[0];
            if(!($out =~ m/0x0$/i))
            {
                log_msg("trace not added with output:$out");
                $traceId = 0; 
            }
            else
            {
                log_msg("trace added with output:$out");    
                $traceId = $traceId + 1 ;
                
            }       
            
        }
        log_msg("valid traces value : $parameters{'validtraces'}");
        if($parameters{'validtraces'} == 1)
        {
            @output =   $telnet->cmd(String =>"test_npapp_trace_activate "." $parameters{'tslot'},"."$parameters{'tport'},"."$parameters{'tvlan'},"."\"$parameters{'tip_add'}\","."$parameters{'tlport'},"."$parameters{'trport'},"."$parameters{'mode'}",Timeout => 10,
                                     Prompt => "/->|acli-shell:/" );
            my $out = @output[0];
            if(!($out =~ m/0x0$/i))
            {
                log_msg("trace not added with output:$out");
                $traceId = 0; 
            }
            else
            {
                log_msg("trace added with output:$out");    
                $traceId = $traceId + 1 ;
                
            }       
            
        }   
        
    }
    else
    {
        log_msg("trace number not supported");
    }
    
    
    
    return $traceId;    
    
}



###################################################################################

#Untaint every input argument(ARGV) and every environmental variable (ENV).
#It is not secure, but we have to do it for now becasue anvil is run with setuid bit

&untaint_ARGV_ENV();

###################################################################################


# *** NOTE *** If wanting to connect via the console connection, precede the port # with 20

###########################*********##############################
# Config (defaults)
my $userpass    = "acme";
my $enablepass  = "packet";
my $vxworkspass = "vxworks";
my $retryCount  = 3;
my $numRetry    = 0;
my $variant     = "DIE HANDLER";

my $returnVal = 1;
my $childrenResults = 0;

my %flowParameters = ( 'rsa'         => '192.168.0.100',
                       'rda'         => '192.168.9.200',
                       'rsp'         => 6655,
                       'rdp'         => 5566,
                       'rvlan'       => 0,
                       'rslot'       => 0,
                       'rport'       => 1,
                       'lsa'         => '172.16.9.200',
                       'lda'         => '172.16.0.100',
                       'lsp'         => 8877,
                       'ldp'         => 7788,
                       'lvlan'       => 0,
                       'lslot'       => 1,
                       'lport'       => 0, 
                       'cl_ip'       => '0x01020202',
                       'cs_ip'       => '0x02020202',        
                       'cvlan'       => 0,
                       'cslot'       => 1,
                       'cport'       => 1,
                       'tslot'       => 0,
                       'tport'       => 0,
                       'tvlan'       => 0,
                       'tip_add'     => '172.16.0.1',
                       'tip_add2'    => '192.168.0.2',
                       'tlport'      => 0,
                       'trport'      => 0,
                       'validtraces' => 0,
                       'mode'        => 0);

my $tracenumber = 1;
my $prenat      = 0;
my $reassemble  = 0;
my $trace_reass = 0;

my %listenerParameters = ('config' => "Listener_Config.txt",
                          'rpcap'  => "",
                          'rif'    => "eth2",
                          'lpcap'  => "",
                          'lpcap2' => "",
                          'lif2'   => "eth3.10",
                          'lif'    => "eth2.10",
                          'lttl '  => 128,
                          'ilttl'  => 128,
                          'tpcap'  => "",
                          'tpcap2' => "");

my %sbcInfo = ( 'sdname' => "",
                'host'   => "",
                'port'   => 23 );


GetOptions( "host=s"       => \$sbcInfo{'host'},
            "port=i"       => \$sbcInfo{'port'},
            "sdname=s"     => \$sbcInfo{'sdname'},

            "rsa=s"         => \$flowParameters{'rsa'},
            "rda=s"         => \$flowParameters{'rda'},
            "rsp=i"         => \$flowParameters{'rsp'},
            "rdp=i"         => \$flowParameters{'rdp'},
            "rvlan=i"       => \$flowParameters{'rvlan'},
            "rslot=i"       => \$flowParameters{'rslot'},
            "rport=i"       => \$flowParameters{'rport'},
            "rpcap=s"       => \$listenerParameters{'rpcap'},
            "rif=s"         => \$listenerParameters{'rif'},
            "lsa=s"         => \$flowParameters{'lsa'},
            "lda=s"         => \$flowParameters{'lda'},
            "lsp=i"         => \$flowParameters{'lsp'},
            "ldp=i"         => \$flowParameters{'ldp'},
            "lvlan=i"       => \$flowParameters{'lvlan'},
            "lslot=i"       => \$flowParameters{'lslot'},
            "lport=i"       => \$flowParameters{'lport'},
            "lif=s"         => \$listenerParameters{'lif'},
            "lif2=s"        => \$listenerParameters{'lif2'},
            "lttl=i"        => \$listenerParameters{'lttl'},
            "ilttl=i"       => \$listenerParameters{'ilttl'},
                
            "cl_ip=s"       => \$flowParameters{'cl_ip'},
            "cs_ip=s"       => \$flowParameters{'cs_ip'},
            "cvlan=i"       => \$flowParameters{'cvlan'},
            "cslot=i"       => \$flowParameters{'cslot'},
            "cport=i"       => \$flowParameters{'cport'},

            "tslot=i"       => \$flowParameters{'tslot'},
            "tport=i"       => \$flowParameters{'tport'},
            "tvlan=i"       => \$flowParameters{'tvlan'},
            "tip_add=s"     => \$flowParameters{'tip_add'},
            "tip_add2=s"    => \$flowParameters{'tip_add2'},
            "tlport=i"      => \$flowParameters{'tlport'},
            "trport=i"      => \$flowParameters{'trport'},
            "tmode=i"       => \$flowParameters{'tmode'},
            "tpcap=s"       => \$listenerParameters{'tpcap'},
            "tpcap2=s"      => \$listenerParameters{'tpcap2'},
            "validtraces=i" => \$flowParameters{'validtraces'},
            "lpcap=s"       => \$listenerParameters{'lpcap'},
            "lpcap2=s"      => \$listenerParameters{'lpcap2'},
            
            "retry=i"       => \$retryCount,
            "tracenumber=i" => \$traceNumber,
            "prenat=i"      => \$prenat,
            "reassemble=i"  => \$reassemble,
            "trace_reass=i" => \$trace_reass,
            "regress=i"     => \$regressCount );

#######################

if(!defined($ENV{'RESULT_SCRIPT'}))
{
    $ENV{'RESULT_SCRIPT'} = "echo";
}

unless($sbcInfo{'host'})
{
    log_msg("Please specify a host(console server ip)");
    $variant = "Did not specify host";
    exit 1;
}
my $session = Net::Telnet->new( Host => $sbcInfo{'host'}, Port => $sbcInfo{'port'} );
$session->input_log(*STDOUT);

if (!defined ($session))
{
    log_msg("Cannot connect to sd host $sbcInfo{'host'}: $!");
    $variant = "Could not connect to host $sbcInfo{'host'}";
    exit 1;
}
log_msg("\nConnected to the console server. Starting script...");

if( sdGoToShellPrompt( Session => $session, Name => $sbcInfo{'sdname'} ) )
{
    log_msg("ERROR: Could not reach shell '->' prompt.");
    $variant = "Could not reach shell prompt.";
    exit 1;
}
else
{
    log_msg("Arrived at shell prompt");
}

my $stype      = 0; #can be used in test cases
my $err        = -1;
my $cServerSet = 0;

my $tId        = 0;
my $traceType  = 0 ;
my $numSuccess = 1;
my $parent_pid = $$;

my $flow = Acme::Flow->new(Session => $session, Name => $sbcInfo{'sdname'});
if(!defined($flow))
{
    log_msg("Can't create Flow object: $!");
    $variant = "Unable to create flow object.";
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

if($flow->ppxFlowApply() != 0)
{
    log_msg("Could not create static flow, exiting...");
    $variant = "Could not create static flow.";
    exit 1;
}


log_msg("FG Index: " . $flow->getFgIndex());

$cServerSet = captureRecServer (Telnet => $session, Parameters => \%flowParameters,stype => $stype);

if ($cServerSet == 1)
{
        
    $tId = captureRecActivate(Telnet =>$session,Parameters => \%flowParameters,tracenumber=>$traceNumber);
    if($tId == 0)
    {
        log_msg("test failed due to trace not being set: $tId");       
    }
    log_msg("number of traces set:$tId ");     
}
else
{
    log_msg("Capture server still not set");
    
}
$session->print( "" );
( $prematch, $match ) = $session->waitfor( Match => "/->|acli-shell:/" );
#$session->buffer_empty;


########setting up the SD_listener###########

#Set lpcap depends on if system doing reassemble [anvil has {{cavium & linux} | {!linux & hifn & !6.3.3m1+} | {hifn & linux & !cavium}}]
my $lpcap = $reassemble ? $listenerParameters{'lpcap2'} : $listenerParameters{'lpcap'};

#Set tpcap depends on if fragmented packets sent to trace server are reassembled [anvil has {sd5 | {!linux & hifn & !6.3.3m1+} | {linux & hifn & !cavium}}]
my $tpcap = $trace_reass ? $listenerParameters{'tpcap2'} : $listenerParameters{'tpcap'};

while($numRetry < $retryCount)
{
my @pids = ();
$childrenResults = 0;

if($tpcap ne "")
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
        if ($prenat == 0)   
        {
            $command = "sd_listener --lsa $flowParameters{'cl_ip'}".
                                  " --lda $flowParameters{'cs_ip'}".
                                  " --ilsa $flowParameters{'lsa'}" .
                                  " --ilda $flowParameters{'lda'}" .
                                  " --ilsp $flowParameters{'lsp'}" .
                                  " --ildp $flowParameters{'ldp'}" .
                                  " --lttl $listenerParameters{'lttl'}".
                                  " --ilttl $listenerParameters{'ilttl'}".
                                  " --lif $listenerParameters{'lif2'}" .
                                  " --lpc $tpcap" .
                                  " --tmo 15";
        }
        else 
        {
            $command = "sd_listener --lsa $flowParameters{'cl_ip'}".
                                  " --lda $flowParameters{'cs_ip'}".
                                  " --ilsa $flowParameters{'rsa'}" .
                                  " --ilda $flowParameters{'rda'}" .
                                  " --ilsp $flowParameters{'rsp'}" .
                                  " --ildp $flowParameters{'rdp'}" .
                                  " --lttl $listenerParameters{'lttl'}".
                                  " --ilttl $listenerParameters{'ilttl'}".
                                  " --lif $listenerParameters{'lif2'}" .
                                  " --lpc $tpcap" .
                                  " --tmo 15";
        }   
        
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

log_msg ("$command","MAIN");
my @results = `$command`;
log_msg("SD_Listener Results:\n@results");
@results = trimArray( @results );


###returning Results####
if( !( grep $_ =~ /success/i, @results ) )
{
    $numRetry++;
    log_msg("Failed to recieve expected packets. Retry count: " .
            ($numRetry) . "/$retryCount\n");
}
else
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
        $numSuccess=0;
        last;
    }
    else
    {
        log_msg("Spawned Children failed to recieve expected packets.  " );
        $numRetry++;
    }
    
}
} #Ending retry logic

$session->print("");
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
if(sdGoToAcliPrompt( Session => $session, Name => $sbcInfo{'sdname'} ) )
{
    log_msg("ERROR: Could not reach Acli prompt.");
    $variant = "Could not reach ACLI prompt.";
    exit 1;
}
else
{
    log_msg("Arrived at Acli prompt");
}

$session->print("packet-trace stop all");
($prematch,$match)=$session->waitfor(Match => "/#/");
$session->print("packet-trace remote stop all");
($prematch,$match)=$session->waitfor(Match => "/#/");
log_msg("deactivated all traces");  


#########exit##########
if(!defined($flow->ppxFlowDestroy()))
{
    log_msg("Could not destroy static flow, exiting...");
    $variant = "Unable to destraoy static flow.";
    exit 1;
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

sleep( 1 );

$returnVal = 0;

exit $returnVal;

# This is the last thing to be executed in the script before exiting
END
{
    #Insert fail result if parent exits abnormally.
    if($parent_pid == $$){
        if($? != 0 || $returnVal != 0)
        {
            system ( "$ENV{'RESULT_SCRIPT'} -variant '$variant' -result 'Fail'" );
        }
    }
}

