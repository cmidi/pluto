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
    my $telnet = "";
    my %parameters = ();
    my $error= -1;
    my $serverSet = 1;
    my $match = "" ;
    my $prematch = "" ;
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
    my $telnet = "";
    my %parameters = ();
    my $traceStart = 0;
    my $match = "" ;
    my $prematch = "" ;
    my $traceId = 1;
    
    if (@_ > 0 && (@_ % 2) == 0)
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
            
            
        }       
    }
    log_msg("configuring packet trace");
    $telnet->print("");
    ($prematch,$match) = $telnet->waitfor(Match => "/->|acli-shell:/");
    
    
    my @output =$telnet->cmd(String =>"test_npapp_trace_activate "." $parameters{'lslot'},"."$parameters{'lport'},"."$parameters{'lvlan'},"."\"$parameters{'tip_add'}\","."$parameters{'tlport'},"."$parameters{'trport'},"."$parameters{'mode'}",Timeout => 10,
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
    
    
    return $traceId;        
        
}

###################################################################################

#Untaint every input argument(ARGV) and every environmental variable (ENV).
#It is not secure, but we have to do it for now becasue anvil is run with setuid bit

&untaint_ARGV_ENV();

###################################################################################

$SIG{__DIE__} = \&die_handler;

# *** NOTE *** If wanting to connect via the console connection, precede the port # with 20

#########################
# Config (defaults)
my $returnVal   = 1;
my $numSuccess  = 0;
my $userpass    = "acme";
my $enablepass  = "packet";
my $vxworkspass = "vxworks";
my $cServerSet  = 0; 
my $tId         = 0;
my $match       = "";
my $prematch    = "";
my $intf        = 0;

my %traceParameters = (   'lsa'     => '172.16.0.208',
                          'lda'     => '172.16.0.1',
                          'lsp'     => 8877,
                          'ldp'     => 7788,
                          'lvlan'   => 10,
                          'lslot'   => 0,
                          'lport'   => 0, 
                          'cl_ip'   => '2.2.2.1',
                          'cs_ip'   => '2.2.2.2',   
                          'cvlan'   => 0,
                          'cslot'   => 1,
                          'cport'   => 1,
                          'tip_add' =>'0x010010ac',
                          'tlport'  => 0,
                          'trport'  => 0,
                          'mode'    => 0);

my %listenerParameters = ('config'  => "Listener_Config.txt",
                          'rpcap'   => "",
                          'rif'     => "eth2",
                          'lpcap'   => "",
                          'lif'     => "eth3.10",
                          'lttl '   => 128,
                          'ilttl'   => 128);

my %sbcInfo = ('sdname' => "",
               'host'   => "",
               'port'   => 23 );

my %packetParameters = ('size'         => 256,
                        'type'         => "udp",
                        'numpkts'      => 1,
                        'fragment'     => 0,
                        'fragmentsize' => 100); 


GetOptions("host=s"       => \$sbcInfo{'host'},
           "port=i"       => \$sbcInfo{'port'},
           "sdname=s"     => \$sbcInfo{'sdname'},

           "lsa=s"        => \$traceParameters{'lsa'},
           "lda=s"        => \$traceParameters{'lda'},
           "lsp=i"        => \$traceParameters{'lsp'},
           "ldp=i"        => \$traceParameters{'ldp'},
           "lvlan=i"      => \$traceParameters{'lvlan'},
           "lslot=i"      => \$traceParameters{'lslot'},
           "lport=i"      => \$traceParameters{'lport'},
           "lif=s"        => \$listenerParameters{'lif'},
           "lttl=i"       => \$listenerParameters{'lttl'},
           "ilttl=i"      => \$listenerParameters{'ilttl'},
           "lpcap=s"      => \$listenerParameters{'lpcap'},
           "cl_ip=s"      => \$traceParameters{'cl_ip'},
           "cs_ip=s"      => \$traceParameters{'cs_ip'},
           "cvlan=i"      => \$traceParameters{'cvlan'},
           "cslot=i"      => \$traceParameters{'cslot'},
           "cport=i"      => \$traceParameters{'cport'},
           "tip_add=s"    => \$traceParameters{'tip_add'},
           "tlport=i"     => \$traceParameters{'tlport'},
           "trport=i"     => \$traceParameters{'trport'},
           "tmode=i"      => \$traceParameters{'tmode'},
           "psize=i"      => \$packetParameters{'size'},
           "ptype=s"      => \$packetParameters{'type'},
           "pnum=i"       => \$packetParameters{'numpkts'},
           "dofrag=i"     => \$packetParameters{'fragment'},
           "fragsize=i"   => \$packetParameters{'fragmentsize'});

##########################

sub die_handler
{
    system ( "$ENV{'RESULT_SCRIPT'} -variant 'DIE HANDLER' -result 'Fail'" );
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

if ($traceParameters{'lslot'}==0 && $traceParameters{'lport'}==0)
{
    $intf = 0;
}
elsif($traceParameters{'lslot'}==0 && $traceParameters{'lport'}==1)
{
    $intf = 2;
}
elsif($traceParameters{'lslot'}==1 && $traceParameters{'lport'}==0)
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

$cServerSet = captureRecServer (Telnet => $session, Parameters => \%traceParameters);

if ($cServerSet == 1)
{
    log_msg("trace server set correctly setting up trace");
    $tId =  captureRecActivate(Telnet =>$session,Parameters => \%traceParameters);
    if($tId == 0)
    {
        $numSuccess = 1;
        log_msg("Test failed because trace was not set correctly or already present trace");
        
    }
    else
    {   
        log_msg("trace started");
    }
}


my @pids;
my $pid = fork();


if ($pid != 0)
{
    push(@pids,$pid);
    log_msg("Parent process, inserting child pid = $pid");
    sleep (1);
}
else
{
    log_msg("Child process!", "CHILD");

    #Run SD Listener and return its result
    $command = "sd_listener --lsa $traceParameters{'cl_ip'}".
                          " --lda $traceParameters{'cs_ip'}".
                          " --ilsa $traceParameters{'lsa'}" .
                          " --ilda $traceParameters{'lda'}" .
                          " --ilsp $traceParameters{'lsp'}" .
                          " --ildp $traceParameters{'ldp'}" .
                          " --lttl $listenerParameters{'lttl'}".
                          " --ilttl $listenerParameters{'ilttl'}".
                          " --lif $listenerParameters{'lif'}" .
                          " --lpc $listenerParameters{'lpcap'}" .
                          " --tmo 30";

    log_msg("Executing: $command\n", "CHILD");
    
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


$session->print("");

($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
$session->print("shellSendPktClear");
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
$session->print("shellSendPktCfg "."\"srcip,destip\"," .
                "\"$traceParameters{'lsa'}\"," .
                "\"$traceParameters{'lda'}\"" );
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
$session->print("shellSendPktCfg "."\"srcport,destport,vlan,numpkts,payloadsize,debug,proto\", " ."$traceParameters{'lsp'},"."$traceParameters{'ldp'},"."$traceParameters{'lvlan'},"."$packetParameters{'numpkts'},"."$packetParameters{'size'},"."0,"."\"$packetParameters{'type'}\"");
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );

#NBT
#slot/port doesn't exist in earlier versions of shellSendPkt. 
#Setting it here will do nothing, then use the $intf value provided. (old)
#If slot/port is set, shellSendPkt will ignore the $intf value provided here and appropriately map slot/port to a linux style interface. (new)

$session->print("shellSendPktCfg "."\"slot, port\"," ."$traceParameters{'lslot'},"."$traceParameters{'lport'}");
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
$session->print("shellSendPktCfg "."\"interface\"," ."$intf");
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );

$session->print("shellSendPktCfg "."\"dofrag\"," ."$packetParameters{'fragment'}");
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );

if($packetParameters{'fragment'})
{
    $session->print("shellSendPktCfg "."\"fragmentsize\","."$packetParameters{'fragmentsize'}");
    ($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );
}
$session->print("shellSendPkt");
($prematch,$match)= $session->waitfor(Match => "/->|acli-shell:/" );

foreach (@pids)
{
    my $tmp = waitpid($_,0);            
    $? = $? >> 8;   
    log_msg("Child $tmp finished with result $?");  
    $numSuccess = $?;
    log_msg ("$numSuccess");    
}

if(sdGoToAcliPrompt( Session => $session, Name => $sbcInfo{'sdname'} ) )
{
    log_msg("ERROR: Could not reach Acli prompt.");
    exit 1;
}
else
{
    log_msg("Arrived at Acli prompt");       
}
$session->print("packet-trace stop all");
($prematch,$match)=$session->waitfor(Match => "/#/");
log_msg("deactivated all traces"); 


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
        system ( "$ENV{'RESULT_SCRIPT'} -variant1 'return nonzero' -result 'Fail'" );
    }
    
}










