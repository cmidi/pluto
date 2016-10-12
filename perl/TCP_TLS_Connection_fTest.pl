#!/usr/bin/perl

#TCP/TLS  script 1 connection testing maximum 20 connections
#written by Cmidha(05-07-2013)

#
# Client IP/port if required

use Acme::embtestlib;
use Acme::Flow;
use Time::HiRes qw( usleep );
use Net::Telnet;
#use Net::SFTP::Foreign;
use Data::Dumper;
use Digest::MD5;
use POSIX qw(strftime);
use POSIX qw/ceil/;
use Getopt::Long;
use Errno;
use Switch;
use Cwd;
use warnings;


####################################Functions########################################
#####################################################################################


#### This subroutine is designed to use the tc/netem linux modules for traffic control
#### and network emulation. This routine can be used to simulate Latency, loss and duplication
#### of data on an interface to test real time network scenarios.
#### This routine would also help in testing re-ordering of packets
#### uses commands /sbin/tc xx xx xx netem xx xx xx
my $FAILURE = "";
sub networkEmulation
{
    my %emulatorParams     = %{$_[0]};
    my %parameters         = %{$_[1]};
    my $task               = $_[2];
    my $session            = $_[3];
    my @results;
    my $ExtradeviceFilter;
    my $qdiscCommand       = "sudo /sbin/tc qdisc";
    my $filterCommand      = "sudo /sbin/tc filter";
    my $setDevicePrio      = "$qdiscCommand add dev $emulatorParams{'dev'} root handle 1: prio";
    
    my $emulateDelay      = "$qdiscCommand add dev $emulatorParams{'dev'} parent 1:1".
                            " netem delay $emulatorParams{'delay'} $emulatorParams{'jitter'}"; 
    my $emulateLoss       = "$qdiscCommand add dev $emulatorParams{'dev'} parent 1:1".
                            " netem loss $emulatorParams{'loss'}"; 
    my $emulateDup        = "$qdiscCommand add dev $emulatorParams{'dev'} parent 1:1".
                            " netem duplicate $emulatorParams{'dup'}";
    my $emulateOrd        =  "$qdiscCommand add dev $emulatorParams{'dev'} parent 1:1".
                             "netem gap 5 delay $emulatorParams{'delay'}";
    
    if($task eq 'show')
    {
        @results = `$qdiscCommand show dev $emulatorParams{'dev'}`;
        foreach(@results)
        {
            print "$_\n";
            if(/RTNETLINK/)
            {
                log_msg("\n********!!!!Error: Could not show!!!!**************\n");
            }
        }
        return 0 ;
    }
    if($task eq 'del')
    {
        print ("delete command: $qdiscCommand del dev $emulatorParams{'dev'} root \n");
        @results = `$qdiscCommand del dev $emulatorParams{'dev'} root`;
        foreach(@results)
        {
            print $_;
            if(/RTNETLINK/ && (/Invalid argument/ || /No such device/))
            {
                log_msg("\n********!!!!Error: Could not del!!!!**************\n");
            }
        }
        return 0;
    }
    ### The filter mechanism basically does step addition to the already present filter
    ### based on the subtype, you can specify your filter too. 
    switch($emulatorParams{'subtype'})
    {
        
        case /^ACK/i 
        {
            $deviceFilter   =       "$filterCommand add dev $emulatorParams{'dev'} protocol ". 
                                    "ip parent 1:0 u32 match ip dst $parameters{'pra'}  match ".
                                    "ip protocol 6 0xff  match ip sport $parameters{'crp'} 0xffff match u8 ". 
                                    "0x10 0xff at 33 flowid 1:1";    

           $ExtradeviceFilter   =  "$filterCommand add dev $emulatorParams{'dev'} protocol ". 
                                    "ip parent 1:0 u32 match ip dst $parameters{'pra'}  match ".
                                    "ip protocol 6 0xff  match ip sport $parameters{'crp'} 0xffff match u8 ". 
                                    "0x10 0xf0 at 33 flowid 1:1";    
        
        }
        case /^SYNACK/i 
        {
            $deviceFilter   =        "$filterCommand add dev $emulatorParams{'dev'} protocol ". 
                                    "ip parent 1:0 u32 match ip dst $parameters{'pra'} match ".
                                    "ip protocol 6 0xff  match ip dport $parameters{'sdCPort'} 0xffff match u8 ". 
                                    "0x12 0xff at 33 flowid 1:1";    
        }        
        case /^SPECIFY/i
        {
            $deviceFilter   = $emulatorParams{'filter'};
        }
        else
        {
            $deviceFilter    =  "$filterCommand add dev $emulatorParams{'dev'} protocol ip parent 1:". 
                              " prio 1 u32 match ip dst $parameters{'pra'} flowid 1:1";
        }
    }
    if($task eq 'add')
    { 
        print ("Running Command : $setDevicePrio\n");
        @results = `$setDevicePrio`;
        foreach(@results)
        {
            print $_;
            if(/RTNETLINK/)
            {
                log_msg("\nError: Could not set dev prio\n");
            }
        }
        print ("Running Command : $deviceFilter\n");
       
        @results = `$deviceFilter`;
        foreach(@results)
        {
            print "$_\n";
            if(/RTNETLINK/)
            {
                log_msg("Error: Could not set filter");
            }
        }
        print ("Running Command :$ExtradeviceFilter\n");
       
        @results = `$ExtradeviceFilter`;
        foreach(@results)
        {
            print "$_\n";
            if(/RTNETLINK/)
            {
                log_msg("Error: Could not set filter");
            }
        }
        
        if($emulatorParams{'test'} eq 'delay')
        {
            print ("Running Command : $emulateDelay\n");
            @results = `$emulateDelay`;
            foreach(@results)
            {
                print "$_\n";
                if(/RTNETLINK/)
                {
                    log_msg("Error: Could not set Delay");
                }
            }    
        }
        if($emulatorParams{'test'} eq 'loss')
        {
            print ("Running Command : $emulateLoss\n");
            @results = `$emulateLoss`;
            foreach(@results)
            {
                print "$_\n";
                if(/RTNETLINK/)
                {
                    log_msg("Error: Could not set loss\n");
                }
            }
        }
        if($emulatorParams{'test'} eq 'dup')
        {
            print ("Running Command : $emulateDup\n");
            @results = `$emulateDup`;
            foreach(@results)
            {
                print "$_\n";
                if(/RTNETLINK/)
                {
                    log_msg("Error: Could not set duplication");
                }
            }
        }
        if($emulatorParams{'test'} eq 'reorder') 
        {
            print ("Running Command : $emulateOrd\n");
            @results = `$emulateOrd`;
            foreach(@results)
            {
                print "$_\n";
                if(/RTNETLINK/)
                {
                    log_msg("Error: Could not set reorder");
                }
            }
        }
       
    }
    
}

####Sub to create certificate request and certificates and importing them to SD
sub importTLSCertificates
{
    # args
    my $session             = $_[0];
    my %parameters          = %{$_[1]};  
    my %ftpInfo             = %{$_[2]};

    my @output;
    my @results;
    my $CSRFile             = "/home/embtest/certificates/embtest/request.csr";
    my $configFile          = "/home/embtest/certificates/embtest/openssl.cnf";
    my $localCert           = "/home/embtest/certificates/embtest/localCert.cert";
    my $localCertCA         = "/home/embtest/certificates/embtest/localCertCA.pem";
    my $certificateRequest  = "generate-certificate-request localCert";
    my @output1;
    my $certificateThere    = 0;
    my $opensslCertificate  = "openssl ca -batch -config $configFile -in $CSRFile -out $localCert";
    my $importCertificate   = "import-certificate x509 localCert localCert.cert";
    my $importCertificateCA = "import-certificate x509 localCertCA localCertCA.pem";
    my $flag                = 0;
    my $authenticate        = 0;
    log_msg("Opening request.csr file : $CSRFile\n");
    open FILE,"+>$CSRFile" or die "$!\n";



    #First create a certificate request and capture output and create file
    log_msg("Trying to create a certificate request : $certificateRequest");
    
    if(sdGoToAcliPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
    {
        log_msg("ERROR: Could not reach Acli prompt.");
        $FAILURE = "ACLI PROMPT";
        exit 1;
    }
   
    @output = $session->cmd(String=>"$certificateRequest",Timeout=>120,Prompt=>"/#/");
    log_msg("PRINT to file");
    foreach (@output)
    {
        if(/Cannot/ && /re-generate/ && /certificate/)
        {
            $flag = 1;
        }
        
        print FILE $_;
        #last if($_ =~ m/-----END CERTIFICATE REQUEST-----/i);
    }
    
    ### Create certificate using request via openssl 
  if($flag) 
  {
     log_msg("Certificate already exists");      
  }
  ### Only create cerfificate and import it once for a suite
  else
  {
    log_msg("creating SD certificate with : $opensslCertificate");
    @results = `$opensslCertificate`;
    foreach(@results)
    { 
        print($_);
    }
    #SCP the certificates to the ramdrv

    if(sdGoToLinuxPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
    {
        log_msg("ERROR: Could not reach Acli prompt.");
        exit 1;
    }
    @output = $session->cmd(String=>"scp embtest\@172.30.44.199:/home/embtest/certificates/embtest/localCertCA.pem /ramdrv",Timeout=>10,Prompt=>"/Password:|connecting/");
    foreach(@output)
    {
        
        if(/continue/)
        {
            log_msg("authentication required");
            $authenticate = 1;
        }
    }
    if($authenticate)
    {
        $session->buffer_empty;
        $session->print("y");
        ( $prematch, $match ) = $session->waitfor( Match => "/Password:/" );
    }
    else
    {
        $session->buffer_empty;        
    }
    $session->print("abc123");
    ( $prematch, $match ) = $session->waitfor( Match => "/#/" );
    
    @output = $session->print("scp embtest\@172.30.44.199:/home/embtest/certificates/embtest/localCert.cert /ramdrv");
    ( $prematch, $match ) = $session->waitfor( Match => "/Password:/" );
    $session->print("abc123");
    
  
############################


############################


###########################
    ( $prematch, $match ) = $session->waitfor( Match => "/#/" );
    #Goto Acli and import the certificate but first check if certificate present
    my @temp = $session->cmd(String=>"exit",Timeout=>10,Prompt=>"/#/");
    #@output1 = $session->cmd(String=>"show directory /opt",Timeout=>10,Prompt=>"/#/");
    #foreach(@output1)
    #{
     #   if(/localCert/ && /cert/)
      #  {
            $certificateThere++;
            log_msg("Found client certificate");
       # }
       # if(/localCert/ && /pem/)
       # {
            $certificateThere++;
            log_msg("Found CA certificate");
        
    #}    
    if($certificateThere >= 2)
    {
        ##### Certificates are ftped now import them to specified certificate record
        log_msg("importing certificate with command: $importCertificate");
        @output = $session->cmd(String=>"$importCertificate",Timeout=>120,Prompt=>"/#/");
        
        
        ###import CA certificate
        log_msg("importing CA certificate with command: $importCertificateCA");
        @output = $session->cmd(String=>"$importCertificateCA",Timeout=>120,Prompt=>"/#/");
    }
    else
    {
        log_msg("--------------Test Failed Could not find certificate-------------------");
        exit 1;
    }
    $session->cmd(String=>"save-config",Timeout=>120,Prompt=>"/#/");
    $session->cmd(String=>"activate-config",Timeout=>120,Prompt=>"/#/");
    $session->print("reboot force");
    if(sdGoToAcliPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
    {
        log_msg("ERROR: Could not reach Acli prompt.");
        exit 1;
    }
    log_msg("Certificate import complete");
  }
}

sub forkListenerInstance(@)
{
    %parameters = %{$_[0]};
    #my @pidList = $_[1];
    %pidsToChild = %{$_[2]}; 
    my $pid = 0;
    my $command = "";
    
    $pid = fork();
    if($pid)
    {
        #Parent
        
        push(@{$_[1]}, $pid);
        $pidsToChild{$$}   = "Parent";
        $pidsToChild{$pid} = "Listener";
        log_msg("Forking, pid is $pid, which is $pidsToChild{$pid} thread parent $$");
    }
    elsif($pid == 0)
    {
        #Child
        #Run SD Listener and return its result
       
        $command =   "sd_listener --lsa $parameters{'lsa'}" .
	                        " --lda $parameters{'lda'}" .
				" --lsp $parameters{'lsp'}" .
				" --ldp $parameters{'ldp'}" .
				" --lif $parameters{'lif'}" .				
				" --lpc $parameters{'lpcap'}" .
				" --tmo 60";
	
        log_msg("Executing: $command\n");
	
        my @results = `$command`;
        log_msg("SD_Listener Results:\n@results");
        @results = trimArray( @results );
	
        if((grep $_ =~ /success/i, @results))
        {
	    print("Success: Received the expected packets.\n");
	    exit 0;
        }
	else {   
	    print("Failure: Did not receive expected packets.\n");
	    exit 1;  
	}
    }
    else
    {

        die "Couldn't fork: $!\n";
    }
}

sub getIDs(@) {

    my @results   = @{$_[0]};
    my $netflow   = $_[1];
    my $hostflow  = $_[2];

    foreach(@results){
	
	if ( /Port/ && /FlowToNet/ && /FlowToHost/ ){
	    
	    my @temp = split( /,\s/, $_, 3);
	    
	    ($trash, $temp[0]) = split( /:\s/, $temp[0]);
	    ($trash, $temp[1]) = split( /:\s/, $temp[1]);
	    ($trash, $temp[2]) = split( /:\s/, $temp[2]);
	    
	    
	    push(@$netflow, $temp[1]);
	    push(@$hostflow, $temp[2]);
	          
	}
    }
    
}

sub SDsetupServerConfig
{
    my $telnet      = $_[0];
    my %parameters  = %{$_[1]};  
    my $error       = 0;
    my $netflow     = $_[2];
    my $hostflow    = $_[3];
    my $ServerStart = "";
    
    if($parameters{'stype'} eq 'TCP')
    {
        $ServerStart = "transport_test_tcp_server_start ".
                         "\"$parameters{'pra'}\"\, ".
                              "$parameters{'prp'}, ".
                                    "\"0.0.0.0\"\, ".
                    "\"$parameters{'sProfile'}\"\, ".
                            "$parameters{'sslot'}, ".
                            "$parameters{'sport'}, ".
                              "$parameters{'svlan'}";
    }
    elsif($parameters{'stype'} eq 'TLS')
    {
        $ServerStart = "transport_test_tls_server_start ".
                         "\"$parameters{'pra'}\"\, ".
                              "$parameters{'prp'}, ".
                                    "\"0.0.0.0\"\, ".
                    "\"$parameters{'sProfile'}\"\, ".
                            "$parameters{'sslot'}, ".
                            "$parameters{'sport'}, ".
                              "$parameters{'svlan'}" ;
    }    
  
    
   my  @results = $telnet->cmd(String => "$ServerStart",
			    Timeout  => 10, Prompt => "/->/");
    foreach(@results){
        if( /err/ ){
	    log_msg("ERROR: Creating Server.");
            $error = -1;
        }
    }
    getIDs(\@results, $netflow,$hostflow);
    return $error;
}


#########################################################################################
##########################################################################################

###################################################################################

#Untaint every input argument(ARGV) and every environmental variable (ENV).
#It is not secure, but we have to do it for now becasue anvil is run with setuid bit

&untaint_ARGV_ENV();
$SIG{__DIE__} = \&die_handler;
###################################################################################
$reconnect = 0;

%transportTTargs = ( 'pra'        => "",
                     'prp'        => "",
                     'sra'        => "",
                     'srp'        => "",
                     'cra'        => "",
                     'crp'        => "",
                     'sdcra'      => "",       
                     'stype'      => "",
                     'ctype'      => "",
                     'test'       => "",
                     'length'     => "",
                     'tmo'        => "",
                     'threads'    => "",
                     'connection' => "",
                     'testfile'   => "",                     
                     'sdCPort'    => "",
                     'sProfile'   => "",
                     'cslot'      => "",
                     'cport'      => "",
                     'sslot'      => "", 
                     'sport'      => "",
                     'svlan'      => "",
                     'cvlan'      => "",
                     'keyfile'    => "",
                     'cProfile'   => "" );
             
             
             
%ftpInfo = ( 'login' => "user",
	     'pass'  => "acme",
	     'IP'    => "",
             'file'  => "" ); 
             

%sbcInfo = ( 'host'      => "",
             'port'      => "",
             'cPort'     => 0,
             'sdname'    => "" );

#Network emulator parameters used in tc/netem modules
%emulatorParams = ( 'test'    => "",
                    'subtype' => "",
                    'delay'   => "",
                    'jitter'  => "",
                    'loss'    => "",
                    'filter'  => "",
                    'dup'     => "",
                    'dev'     => "",
                    'reorder' => "" );

%listener = ('lsa'       => "",
	     'lda'       => "",
	     'lsp'       => "",
	     'ldp'       => "",
	     'lvlan'     => "",
	     'lif'       => "",
	     'lpcap'     => "",
             'test'      => "" );

%pidsToChild ;

GetOptions ( "host=s"    => \$sbcInfo{'host'},
             "port=i"    => \$sbcInfo{'port'},
             "sdname=s"  => \$sbcInfo{'sdname'},
             "caviump=i" => \$sbcInfo{'cPort'},
	    
	     "tc=s"      => \$emulatorParams{'test'},
             "type=s"    => \$emulatorParams{'subtype'},
             "delay=s"   => \$emulatorParams{'delay'},
             "jitter=s"  => \$emulatorParams{'jitter'},
             "loss=s"    => \$emulatorParams{'loss'},
             "dev=s"     => \$emulatorParams{'dev'},
             "dup=s"     => \$emulatorParams{'dup'},
             "reorder=s" => \$emulatorParams{'reorder'},
                            
             "pra=s"     => \$transportTTargs{'pra'},
	     "sra=s"     => \$transportTTargs{'sra'},
             "cra=s"     => \$transportTTargs{'cra'},
             "crp=i"     => \$transportTTargs{'crp'},
             "sdcra=s"   => \$transportTTargs{'sdcra'},
	     "prp=i"     => \$transportTTargs{'prp'},
	     "srp=i"     => \$transportTTargs{'srp'},
	     "thread=i"  => \$transportTTargs{'threads'},
	     "conn=i"    => \$transportTTargs{'connection'},
	     "len=i"     => \$transportTTargs{'length'},
	     "tmo=i"     => \$transportTTargs{'tmo'},
	     "stype=s"   => \$transportTTargs{'stype'},
             "ctype=s"   => \$transportTTargs{'ctype'},
             "tfile=s"   => \$transportTTargs{'testfile'},
             "sProfile=s"=> \$transportTTargs{'sProfile'},
             "cProfile=s"=> \$transportTTargs{'cProfile'},
             "cslot=i"   => \$transportTTargs{'cslot'},
             "cport=i"   => \$transportTTargs{'cport'},
             "sport=i"   => \$transportTTargs{'sport'},
             "sslot=i"   => \$transportTTargs{'sslot'},
             "svlan=i"   => \$transportTTargs{'svlan'},
             "cvlan=i"   => \$transportTTargs{'cvlan'},
             "sdCPort=i" => \$transportTTargs{'sdCPort'}, 
             "test=i"    => \$transportTTargs{'test'},
             
             "pcap=s"    => \$listener{'lpcap'},
             "ltest=s"   => \$listener{'test'},
             "lsa=s"     => \$listener{'lsa'},  
             "lda=s"     => \$listener{'lda'},  
             "lsp=i"     => \$listener{'lsp'},
             "ldp=i"     => \$listener{'ldp'},
             "lvlan=i"   => \$listener{'lvlan'},               
               
             "r=i"       => \$reconnect,
       	     "ftplogin=s"=> \$ftpInfo{'login'},
	     "ftppass=s" => \$ftpInfo{'pass'},
	     "ftpip=s"   => \$ftpInfo{'IP'},
             "ftpfile=s" => \$ftpInfo{'file'},
             "key=s"     => \$transportTTargs{'keyfile'});

	     

             
#############################################################################
my $prematch       = "";
my $match          = "";
my $filesnumber        ;
my $md5sum         = "";
my $i              = 0;
my $wildcard       = "Test*";
my $backup         = "Fail";
my @FlowsNet;
my @FlowsHost;
my @pids;
my $childResults   =  0;
my $sentreceive    =  0;
my $receive        =  0;
my $clientSet      = "";
my $startTT        = "";
my $returnVal = 0;
my @ipConnections  = "";
my @memStats       = "";
my @inuseMem           ;
my @maxMem             ;
my @inuseMemNew        ;
my @maxMemNew          ;
my $CSRFile        = "/home/embtest/certificates/embtest/request.csr";
my $localCert      = "/home/embtest/certificates/embtest/localCert.cert";
my $delete         = "del";
my $show           = "show";
my $add            = "add";
$listener{'lif'}   = $emulatorParams{'dev'};               

#Verify we have proper input. 
sub die_handler
{
    if($emulatorParams{'test'} ne "")
    {
        log_msg("\n----------------Delete current rules on Dying----------------\n");
        networkEmulation(\%emulatorParams,\%transportTTargs,$delete);
    }
    log_msg("Remove Test Files on dying\n");
    `rm -rf $wildcard`;
    log_msg("Remove errorlog on dying\n");
    `rm -rf errorlog.txt`;

    system ( "$ENV{'RESULT_SCRIPT'} -variant 'DIE_HANDLER' -result 'Fail'" );
}

if(!defined($ENV{'RESULT_SCRIPT'}))
{
    $ENV{'RESULT_SCRIPT'} = "echo";
}

unless( $sbcInfo{'host'} && $sbcInfo{'port'} )
{
    log_msg("ERROR: Please specify a host(console server ip) and port.");
    exit 1;
}

my $serverSet = 0;
#Set up Telnet
my $session = Net::Telnet->new( Host => $sbcInfo{'host'}, Port => $sbcInfo{'port'} );
$session->input_log( *STDOUT );


$session->binmode(1);

if ( !defined( $session ) )
{
    log_msg("ERROR: Can not connect to SD HOST $sbcInfo{'host'}: $!");
    exit 1;
}

###if TLS tests import certificates
if($transportTTargs{'ctype'} eq 'TLS')
{
    unless ( $ftpInfo{'login'} && $ftpInfo{'pass'} && $ftpInfo{'IP'} )
    {
         log_msg("Specify user name and password for FTP login.");
         exit 1;
    }
    importTLSCertificates($session,\%transportTTargs,\%ftpInfo);
   
}


if(sdGoToAcliPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
{
    log_msg("ERROR: Could not reach Acli prompt.");
    exit 1;
}
print("\n");
print("\n");
print("---------------------------STARTING DEBUG COMMANDS BEOFRE TEST----------------------------\n");

@ipConnections = $session->cmd(String=>"show ip connections",Timeout=>30,Prompt=>"/#/");
@memStats      = $session->cmd(String=>"show datapath etc-stats memory",Timeout=>30,Prompt=>"/#/");
push(@inuseMem,0);
foreach(@memStats)
{    
   for($i=0;$i<8;$i++)
   {
         if(/^$i\s*[0-9]{0,4}\s*[0-9]{0,9}\s*[0-9]{0,9}\s*\([0-9]{0,4}\s*\)\s*(\d*)\s*(\d*)/i)
         {
             log_msg("pool $i in use :$1 max : $2");
             push(@inuseMem,$1);
             push(@maxMem,$2);
         }
          
   }
}
print("\n");
print("\n");
print("---------------------------!!!!!!!!DEBUG COMMANDS END!!!!!!!!!----------------------------\n");

print("\n");
print("\n");
print("---------------------------!!!!!!STARTING SCRIPT COMMANDS!!!!!----------------------------\n");

if(sdGoToShellPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
{
    log_msg("ERROR: Could not reach '->' prompt.");
    exit 1;
}

$serverSet = SDsetupServerConfig($session,\%transportTTargs,\@FlowsNet,\@FlowsHost);
if($serverSet < 0)
{
    log_msg("Error: Could not create server");
    exit 1;
}


#start TransportTT
if($transportTTargs{'ctype'} eq 'TLS')
{
    $startTT = "TransportTT --pra $transportTTargs{'pra'}".
                  " --prp $transportTTargs{'prp'} -l $transportTTargs{'length'}".
                  "  -p $transportTTargs{'ctype'}  -P $transportTTargs{'threads'}".  
                  " -n $transportTTargs{'connection'} -f $transportTTargs{'testfile'}". 
                  " --sra $transportTTargs{'sra'}  --srp $transportTTargs{'srp'}".  
                  " -s $transportTTargs{'stype'}   --tmo $transportTTargs{'tmo'}  --type 3 -k $transportTTargs{'keyfile'}";

}
elsif($transportTTargs{'ctype'} eq 'TCP')
{
    $startTT = "TransportTT --pra $transportTTargs{'pra'}".
                  " --prp $transportTTargs{'prp'} -l $transportTTargs{'length'}".
                  "  -p $transportTTargs{'ctype'}  -P $transportTTargs{'threads'}".  
                  " -n $transportTTargs{'connection'} -f $transportTTargs{'testfile'}". 
                  " --sra $transportTTargs{'sra'}  --srp $transportTTargs{'srp'}".  
                  " -s $transportTTargs{'stype'}   --tmo $transportTTargs{'tmo'}  --type 3";
 
}

if($listener{'test'} eq 'ACK')
{
    $startTT =   $startTT." --cla $transportTTargs{'cra'}  --clp $transportTTargs{'crp'}";      
}

my $connections = $transportTTargs{'connection'} * $transportTTargs{'threads'};

if($transportTTargs{'ctype'} eq 'TCP')
{
    $clientSet =     "transport_test_tcp_client_start ".
                     "\"$transportTTargs{'sdcra'}\"\, ".
                      "$transportTTargs{'sdCPort'}, ".
                     "\"$transportTTargs{'sra'}\"\, ".
                          "$transportTTargs{'srp'}, ".
                "\"$transportTTargs{'cProfile'}\"\, ".
                        "$transportTTargs{'cslot'}, ".
                        "$transportTTargs{'cport'}, ".
                        "$transportTTargs{'cvlan'}, ".
                                       "$connections";
}
elsif($transportTTargs{'ctype'} eq 'TLS')
{
    $clientSet =     "transport_test_tls_client_start ".
                     "\"$transportTTargs{'sdcra'}\"\, ".
                      "$transportTTargs{'sdCPort'}, ".
                     "\"$transportTTargs{'sra'}\"\, ".
                          "$transportTTargs{'srp'}, ".
                "\"$transportTTargs{'cProfile'}\"\, ".
                        "$transportTTargs{'cslot'}, ".
                        "$transportTTargs{'cport'}, ".
                        "$transportTTargs{'cvlan'}, ".
                                       "$connections";
}
########## Start network emulation  ################

if($emulatorParams{'test'} ne "")
{
    log_msg("\nStarting Network emulation for tests\n");
    print("----------------Delete current rules before start----------------\n");
    networkEmulation(\%emulatorParams,\%transportTTargs,$delete);
    print("----------------!!!!Show Current Rules!!!-------------------------\n");
    networkEmulation(\%emulatorParams,\%transportTTargs,$show);
    print("----------------!!!!!!Added the rule!!!!!!!!----------------------\n");
    networkEmulation(\%emulatorParams,\%transportTTargs,$add);
    log_msg("\nAdded Network Emulation Rules\n");
}
######### network emulation end ####################


######### SD_Listener istance for testing###########
if(($emulatorParams{'test'} ne "") 
               && ($listener{'test'} ne ""))
{
    log_msg("Forking Listener");
    forkListenerInstance(\%listener, \@pids,\%pidsToChild);
}
###################End##############################



################# Fork for TransportTT##############
$pid = fork();
if($pid)
{
    #parent
    
    push(@pids, $pid);
    $pidsToChild{$pid} = "Transport"; 
    log_msg("Forking, pid is $pid, which is $pidsToChild{$pid} thread parent $$");
    log_msg("Pids: @pids");         
}
elsif($pid == 0)
{
    
  eval
  {  
    local $SIG{ALRM} = sub {die "alarm\n"};
    alarm 400;
    my $ServerSet = 0;
    my $SuccessConnServer = 0;
    my $SuccessConnClient = 0;
    my @resultsTT = `$startTT`;    
    if($listener{'test'} ne "")
    {
        log_msg("Passing the listener test");
       
        switch($listener{'test'})
        {
            case /^ACK/i
            {
               log_msg("Listener ACK Drop Test");
               foreach(@resultsTT)
               { 
                   print $_;
                   if(/^SERVER/)
                   {
                       
                       $ServerSet = 1;
                   }
                   if(/^Successful connections\s*:(\d*)/)
                   {
                       if($ServerSet)
                       {
                           $SuccessConnServer = $1;
                           
                       }
                       else
                       {
                           $SuccessConnClient = $1;
                           
                       }
                   }
                   last if($_ =~ m/Test/i); 
               }
               if(($SuccessConnServer == $connections )&& 
                      ($SuccessConnClient >= ($connections - 1)))
               {
                   log_msg("No Potential Problem in TT");
                   log_msg("client : $SuccessConnClient server : $SuccessConnServer");                   
                   exit (0);
               }
               else
               {   
                   log_msg("Test Failed connections client : $SuccessConnClient server : $SuccessConnServer");                   
                   exit (1);
               } 
            }
            case /^SYNACK/i
            {
               log_msg("Listener SYNACK Drop Test");
               foreach(@resultsTT)
               { 
                   print $_;
                   if(/^SERVER/)
                   {
                       log_msg("Getting Server Stats");
                       $ServerSet = 1;
                   }
                   if(/^Successful connections\s*:(\d*)/)
                   {
                       if($ServerSet)
                       {
                           $SuccessConnServer = $1;
                           
                       }
                       else
                       {
                           $SuccessConnClient = $1;
                           
                       }
                   }
                   last if($_ =~ m/Test/i); 
               }
               if(($SuccessConnClient == $connections )&& 
                      ($SuccessConnServer >= ($connections - 1)))
               {
                   log_msg("No Potential Problem in TT");
                   log_msg("client : $SuccessConnClient server : $SuccessConnServer");                   
                   exit (0);
               }
               else
               {   
                   log_msg("Test Failed connections client : $SuccessConnClient server : $SuccessConnServer");                   
                   exit (1);
               }                                                             
            }
            else
            {
                log_msg("Default Case Listener Pass");
               foreach(@resultsTT)
               {
                   print $_;
               }
               if(grep $_ =~ /Test Failed/i, @resultsTT)
               {
                  log_msg("Test Failed");
                  alarm 0;
                  exit(1);
               }
               else
               {
                  log_msg("Test Passed");
                  alarm 0;
                  exit(0);     
               }  
            }
        } 
     }
     else
     {
         foreach(@resultsTT)
         {
             print $_;
         }
         if(grep $_ =~ /Test Failed/i, @resultsTT)
         {
             log_msg("Test Failed");
             alarm 0;
             exit(1);
         }
         else
         {
             log_msg("Test Passed");
             alarm 0;
             exit(0);     
         }
        
     } 
  };    
  if($@)
  {
      die unless $@ eq "alarm\n";
      log_msg("**********No Reponse for TT**********");
      log_msg("**********Test Failed**********");
      exit(1);
  }
  else
  {}
}
log_msg("Executing TT: $startTT\n");



#######################################END############################
sleep (1);

#start Client on SD
$session->print ("");
($prematch, $match) = $session->waitfor(Match => "/->|acli-shell:/");

my @resultsClient = $session->cmd(String => "$clientSet",Timeout => 40,
                                  Prompt => "/->/" );
    
foreach(@pids)
{
    
    my $tmp = waitpid($_,0);
    $? = $? >> 8;
    log_msg("Child $tmp finished with results $?");
    $childResults += $?;
    if($?)
    {
        $FAILURE = $FAILURE."-".$pidsToChild{$tmp};
    }
}
my $numSuccess = $childResults;
if($numSuccess)
{
    $FAILURE = $FAILURE."-FAILED";
}
############################RECONNECT TEST START#######################
######This test is to test if reconnect to same socket is possible, 
######after a close of connection. This in case will also test closing of a connection

if($reconnect)
{
    sleep 25;
    ######First check socket status fail if socket still in use
    print("---------------------------!!!!!!!!CHECKING SOCKET STATUS!!!!!!!!!!----------------------------\n");
    if(sdGoToAcliPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
    {
        log_msg("ERROR: Could not reach Acli prompt.");
        exit 1;
    }
    @ipConnections = $session->cmd(String=>"show ip connections",Timeout=>30,Prompt=>"/#/");
    #####Parse ipConnections for looking for open sockets####
    
    
   $pid = fork();
   if($pid)
   {
        #parent
        log_msg("Forking for pid is $pid, parent $$");
        push(@pids, $pid); 
        log_msg("Pids: @pids");         
   }
   elsif($pid == 0)
   {
    
       eval
       {  
          local $SIG{ALRM} = sub {die "alarm\n"};
          alarm 200;
          my @resultsTT = `$startTT`;
          foreach(@resultsTT)
          {
               print($_);
          }
          @resultsTT = trimArray(@resultsTT);
        
              if(grep $_ =~ /Test Failed/i, @resultsTT)
              {
                  log_msg("Test Failed");
                  alarm 0;
                  exit(1);
               }
               else
               {
                   log_msg("Test Passed");
                   alarm 0;
                   exit(0);     
               }
          
        };
      if($@)
      {
          die unless $@ eq "alarm\n";
          log_msg("**********No Reponse for TT**********");
          log_msg("**********Test Failed**********");
          exit(1);
      }
      else
      {}
   }
   log_msg("Executing TT: $startTT\n");

   sleep (1);

   #start Client on SD
   $session->print ("");
   ($prematch, $match) = $session->waitfor(Match => "/->|acli-shell:/");

   my @resultsClient = $session->cmd(String => "$clientSet",Timeout => 30,
                                  Prompt => "/->/" );
    
   foreach(@pids)
   {
    
        my $tmp = waitpid($_,0);
        $? = $? >> 8;
        log_msg("Child $tmp finished with results $?");
        $childResults += $?;
   }

   my $numSuccess = $childResults;
   if($numSuccess)
   {
       log_msg("----------*********FAILED IN RECONNECT**********------------\n");
   }
}

###########################RECONNECT TEST END#########################


print("\n");
print("\n");

print("---------------------------!!!!!!END SCRIPT COMMANDS!!!!!!!!!-----------------------------\n");
my $fh;
if(!$numSuccess)
{
    
    my @FileResult = `ls -al $wildcard  | wc -l`;
    foreach(@FileResult)
    {
        log_msg ("Number of files created : $_\n");
        $filesnumber = $_;
    }
    open ($fh, '<',$transportTTargs{'testfile'}) or die "Cannot open test file";
    binmode($fh);
    $md5sum = Digest::MD5->new->addfile($fh)->hexdigest;    
    close($fh);
    my $dir = getcwd();
    #getting directory name
    log_msg("Directory: $dir");
    #getting test file names
    my @fileNames = <$dir/$wildcard>;

    foreach(@fileNames)
    {
        my $filenames = $_;
        
        my @checkFile = split($dir,$filenames);             
        my $checkFile = $checkFile[1];
        $checkFile = substr $checkFile,1;        
        open ($fh, '<',$checkFile) or die "Cannot open check file";
        binmode($fh);
        $sum = Digest::MD5->new->addfile($fh)->hexdigest;
        
        close($fh);
        log_msg("File under test:$checkFile");
        
        log_msg ("md5sum test files :$sum\n"); 
        if($md5sum ne $sum)
        {
	    $numSuccess = 1;
            my @file = split($dir,$filenames);             
            my $file = $file[1];
            $file = substr $file,1;
            my $time = strftime("%a-%b-%Y-%H:%M:%S",localtime); 
            #make it unique by adding timestamp;
            $file = join('.',$file,$time);
            
            my $failedFile = join('.',$backup,$file);
            $failedFile = `mv $filenames logs/$failedFile`;
        }
        
    }    
}
#####get stats before exit####


####Tricky Cavium console stats####
if($sbcInfo{'cPort'})
{
    my $cavSession = Net::Telnet->new( Host => $sbcInfo{'host'}, Port => $sbcInfo{'cPort'} );
    my @caviumStats = "";
    sleep (1);
    $session->cmd(String => "cvmx_stats_ppm 14",Timeout => 10,
                                  Prompt => "/0x0/" );
    for(;;)
    {
    
        $caviumStats = $cavSession->getline(Timeout=>10);
        last if($caviumStats =~ m/TLS STATS END/i);    
        push(@caviumStats,$caviumStats);
    }
    foreach(@caviumStats)
    {
        my @sentreceive;
        my @receive;
        my @performance;
        if(/sent\/received bytes/)
        {
            @sentreceive = split('is\s+',$_);
            $sentreceive = $sentreceive[1];
     
        }
        if(/received bytes/)
        {
            @receive = split('is\s+',$_);
            $receive = $receive[1];
     
        }  
   
     }
     if(($receive == 0) || ($sentreceive == 0) )
     {
         $numSuccess = 0;
         log_msg("Test Failed");
         log_msg("SD did not receive Data");
     }
     log_msg("--------------SD CAVIUM STATS----------------");
     log_msg("Received Bytes: $receive");
     log_msg("Echoed and Received  Bytes: $sentreceive");
     log_msg("----------------SD END STATS-----------------");
}

print("\n");
print("\n");

print("---------------------------STARTING DEBUG COMMANDS AFTER TEST-----------------------------\n");
if(sdGoToAcliPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
{
    log_msg("ERROR: Could not reach Acli prompt.");
    exit 1;
}
@memStats = "";
@ipConnections = "";
@ipConnections = $session->cmd(String=>"show ip connections",Timeout=>30,Prompt=>"/#/");
@memStats      = $session->cmd(String=>"show datapath etc-stats memory",Timeout=>30,Prompt=>"/#/");
push(@inuseMemNew,0);
foreach(@memStats)
{    
   for($i=0;$i<8;$i++)
   {
         if(/^$i\s*[0-9]{0,4}\s*[0-9]{0,9}\s*[0-9]{0,9}\s*\([0-9]{0,4}\s*\)\s*(-?\d*)\s*(-?\d*)/i)
         {
             log_msg("pool $i in use :$1 max : $2");
             push(@inuseMemNew,$1);
             push(@maxMemNew,$2); 
             
         }
                  
   }
}

my $memStart  = 0;
my $memEnd    = 0;
my $memUsage  = 0;
for($i=0;$i<8;$i++)
{
    $memStart = pop(@inuseMem);
    $memEnd   = pop(@inuseMemNew);
    #check to aviod divide by zero
    if($memStart)
    {
        $memUsage = ($memEnd - $memStart)/($memStart);
    }
    else
    {
        $memUsage = ($memEnd - $memStart);
    }
    
    if($memUsage >= 0)
    {
        if(($memUsage*100) > 20 ) 
        {
            my $tempPool = 7 - $i; 
            log_msg("----------!!!!Potential Memory Leak!!!!--------------");
            log_msg("Mem usage is : $memUsage for pool : $tempPool ");
            $numSuccess = $numSuccess++;
            $FAILURE = "$FAILURE"."+LEAK $tempPool ";
        }
    }
    else
    {
         if(($memUsage*(-100)) > 20 ) 
         {
            my $tempPercent = $memUsage*(-100); 
            log_msg("Reduced or neagative usage : $tempPercent end : $memEnd Start : $memStart");
            if($memEnd < 0)
            {
                $numSuccess = $numSuccess++;
            }
        }
    }
}



$session->cmd(String=>"dump-np-stats",Timeout=>10,Prompt=>"/#/");


print("\n");
print("\n");
print("---------------------------!!!!!!!!DEBUG COMMANDS END!!!!!!!!!----------------------------\n");

###cleanup####
print("\n");
print("---------------------------!!!!!!!!!!STARTING CLEANUP!!!!!!!!!----------------------------\n");


########## Stop network emulation  ################

if($emulatorParams{'test'} ne "")
{
    
    log_msg("\nDelete current rules");
    networkEmulation(\%emulatorParams,\%transportTTargs,$delete);
}

######### network emulation end ####################

log_msg("Remove Test Files");
my @cleanup = `rm -rf $wildcard`;
log_msg("Remove errorlog");
my @logCleanup = `rm -rf errorlog.txt`;
log_msg("Remove request and certificate file");
@cleanup = `rm -rf $CSRFile`;
@cleanup = `rm -rf $localCert`;

if(sdGoToAcliPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
{
    log_msg("ERROR: Could not reach Acli prompt.");
    exit 1;
}
#### very very bad idea for clean up but we do not have a clean way to 'clean up' yet ###
$session->print( "reboot force" );
if(sdGoToAcliPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
{
    log_msg("ERROR: Could not reach Acli prompt.");
    exit 1;
}
else
{
    log_msg("Successfully Rebooted for Cleanup");
}

if(!$numSuccess){
    log_msg("Test:                                           PASS");
    system ( "$ENV{'RESULT_SCRIPT'} -variant 'none' -result 'Pass'" );
}
else{
    log_msg("Test:                                           FAIL");
    system ( "$ENV{'RESULT_SCRIPT'} -variant $FAILURE -result 'Fail'" );
    
}



log_msg("Script finished. Exiting..");
exit $returnVal;
# This is the last thing to be executed in the script before exiting
END
{
    # If we are returning something non-zero, insert a fail result
    # Note: This is mainly to protect against the script erroring out before creating a result
    if(($? != 0 || $returnVal != 0) && (defined($pid) && $pid != 0))
    {
        system ( "$ENV{'RESULT_SCRIPT'} -variant $FAILURE -result 'Fail'" );
    }

}



