#!/usr/bin/perl

#TCP/TLS  script 2 performance testing tests
#written by Cmidha(06-25-2013)

#
# Options
# Connections per thread
# Number of client threads
# Number of instances of server and client 
# Client type
# server type
# Test type
# Testfiles
# Buffer length
# TransportTT server ip addresses
# TransportTT server ports
# SD server ip addresses
# SD server ports
# Client IP/port if required
# Slot port for interfaces

# TODO add debug commands
# TODO add variable for handing exits

use Acme::embtestlib;
use Acme::Flow;
use Time::HiRes qw( usleep );
use Net::Telnet;
use Data::Dumper;
use Net::FTP;
use Digest::MD5;
use POSIX qw(strftime);
use POSIX qw/ceil/;
use Getopt::Long;
use Errno;
use Switch;
use Cwd;
use warnings;
use IPC::Shareable;

####################################Functions########################################
#####################################################################################
####Sub to create certificate request and certificates and importing them to SD
sub importTLSCertificates
{
    # args
    my $session = $_[0];
    my %parameters = %{$_[1]};  
    my %ftpInfo = %{$_[2]};

    my @output;
    my @results;
    my $CSRFile = "/home/embtest/certificates/embtest/request.csr";
    my $configFile = "/home/embtest/certificates/embtest/openssl.cnf";
    my $localCert = "/home/embtest/certificates/embtest/localCert.cert";
    my $localCertCA = "/home/embtest/certificates/embtest/localCertCA.pem";
    my $certificateRequest = "generate-certificate-request localCert";
    my @output1;
    my $certificateThere = 0;
    my $opensslCertificate = "openssl ca -batch -config $configFile -in $CSRFile -out $localCert";
    my $importCertificate = "import-certificate x509 localCert localCert.cert";
    my $importCertificateCA = "import-certificate x509 localCertCA localCertCA.pem";
    my $flag = 0;

    log_msg("Opening request.csr file : $CSRFile\n");
    open FILE,"+>$CSRFile" or die "$!\n";



    #First create a certificate request and capture output and create file
    log_msg("Trying to create a certificate request : $certificateRequest");
    
    if(sdGoToAcliPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
    {
        log_msg("ERROR: Could not reach Acli prompt.");
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
    #Log into the FTP.
    my $ftpramdrv="\"\/ramdrv\/\"";
    my $ftp = Net::FTP->new($ftpInfo{'IP'});
    if ( not defined( $ftp ) )
    {
        log_msg("Can't connect to SD FTP $ftpInfo{'IP'}, $!");
        exit 1;
    }
    $ftp->binary();

    $ftp->login($ftpInfo{'login'}, $ftpInfo{'pass'}) or $newErr=1;
    log_msg("FTP Error: Cannot log in.") if $newErr;    
    $ftp->quit if $newErr;
    exit 1 if $newErr;

############################


############################

    #Change to /ramdrv/

    $ftp->cwd("/ramdrv") or $newErr=1;
    log_msg("FTP Error: Can't Cd into dir $ftpramdrv ** $!") if $newErr;    
    $ftp->quit if $newErr;
    exit 1 if $newErr;
    log_msg("Changed to $ftpramdrv.");

    #put the certificates
    $ftp->put("$localCert") or $newErr=1;
    log_msg("FTP Error: Could not put file in /ramdrv") if $newErr;
    $ftp->quit if $newErr;
    $ftp->put("$localCertCA") or $newErr=1;
    log_msg("FTP Error: Could not put file in /ramdrv") if $newErr;
    $ftp->quit if $newErr;
  
    log_msg("FTP complete");
###########################

    #Goto Acli and import the certificate but first check if certificate present
    if(sdGoToAcliPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
    {
        log_msg("ERROR: Could not reach Acli prompt.");
        exit 1;
    }
    @output1 = $session->cmd(String=>"show directory /ramdrv",Timeout=>10,Prompt=>"/#/");
    foreach(@output1)
    {
        if(/localCert/ && /cert/)
        {
            $certificateThere++;
            log_msg("Found client certificate");
        }
        if(/localCert/ && /pem/)
        {
            $certificateThere++;
            log_msg("Found CA certificate");
        }
    }    
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
    $session->print("reboot f");
    if(sdGoToAcliPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
    {
        log_msg("ERROR: Could not reach Acli prompt.");
        exit 1;
    }
    log_msg("Certificate import complete");
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
    my $telnet      =    $_[0];
    my %parameters  = %{$_[1]};  
    my $error       =        0;
    my $netflow     =    $_[2];
    my $hostflow    =    $_[3];
    my $ServerStart =       "";
    my $i           =        0;

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

my $instances=1;

%transportTTargs = ( 'pra'        => "",
                     'prp'        => "",
                     'sra'        => "",
                     'srp'        => "",
                     'stype'      => "",
                     'ctype'      => "",
                     'test'       => "",
                     'length'     => "",
                     'tmo'        => "",
                     'threads'    => "",
                     'connection' => "",
                     'testfile'   => "",
                     'cslot'      => "",
                     'cport'      => "",
                     'sslot'      => "", 
                     'sport'      => "",
                     'svlan'      => "",
                     'cvlan'      => "",
                     'sdCPort'    => "",
                     'sProfile'   => "",
                     'keyfile'    => "",
                     'cProfile'   => "");
           
%sbcInfo = ( 'host'      => "",
             'port'      => "",
             'cPort'     => 0,
             'sdname'    => "" );

%devInfo = ( 'host'      => "",
             'port'      => "",
             'user'      => "",
             'pass'      => "");

%ftpInfo = ( 'login' => "user",
	     'pass'  => "acme",
	     'IP'    => "172.30.44.201",
             'file'  => ""); 

GetOptions ( "host=s"     => \$sbcInfo{'host'},
             "port=i"     => \$sbcInfo{'port'},
             "sdname=s"   => \$sbcInfo{'sdname'},
             "caviump=i"  => \$sbcInfo{'cPort'},
	     "devhost=s"  => \$devInfo{'host'},
             "user=s"     => \$devInfo{'user'},
             "pass=s"     => \$devInfo{'pass'}, 
	     "pra=s"      => \$transportTTargs{'pra'},
	     "sra=s"      => \$transportTTargs{'sra'},
	     "prp=i"      => \$transportTTargs{'prp'},
	     "srp=i"      => \$transportTTargs{'srp'},
	     "thread=i"   => \$transportTTargs{'threads'},
	     "conn=i"     => \$transportTTargs{'connection'},
	     "len=i"      => \$transportTTargs{'length'},
	     "tmo=i"      => \$transportTTargs{'tmo'},
	     "stype=s"    => \$transportTTargs{'stype'},
             "ctype=s"    => \$transportTTargs{'ctype'},
             "tfile=s"    => \$transportTTargs{'testfile'},
             "sProfile=s" => \$transportTTargs{'sProfile'},
             "cProfile=s" => \$transportTTargs{'cProfile'},
             "cslot=i"    => \$transportTTargs{'cslot'},
             "cport=i"    => \$transportTTargs{'cport'},
             "sport=i"    => \$transportTTargs{'sport'},
             "sslot=i"    => \$transportTTargs{'sslot'},
             "svlan=i"    => \$transportTTargs{'svlan'},
             "cvlan=i"    => \$transportTTargs{'cvlan'},
             "instance=i" => \$instances,
             "sdCPort=i"  => \$transportTTargs{'sdCPort'}, 
             "test=i"     => \$transportTTargs{'test'},
             "ftplogin=s" => \$ftpInfo{'login'},
	     "ftppass=s"  => \$ftpInfo{'pass'},
	     "ftpip=s"    => \$ftpInfo{'IP'},
             "ftpfile=s"  => \$ftpInfo{'file'},
             "key=s"      => \$transportTTargs{'keyfile'});

	     

             
#############################################################################
my $prematch      = "";
my $match         = "";
my $filesnumber;
my $md5sum        = "";
my $wildcard      = "Test*";
my $backup        = "Fail";
my @FlowsNet;
my @FlowsHost;
my @pids;
my $childResults  = 0;
my $sentreceive   = 0;
my $receive       = 0;
my $clientSet     = "";
my $startTTServer = "";
my $startTTClient = "";
my $returnVal     = 0;
my @client;
my @servers;
my @TTClient;
my $i             = 0;
my @devSession;
my @clientSession;
my $CSRFile = "/home/embtest/certificates/embtest/request.csr";
my $localCert = "/home/embtest/certificates/embtest/localCert.cert";

######Shared Data common to all processes using shared memory
$cHandle = tie $totalConnections, 'IPC::Shareable',undef,{destroy =>1}
or die "Could not share variable $!";
$scHandle = tie $totalServerConnections, 'IPC::Shareable',undef,{destroy =>1}
or die "Could not share variable $!";
$dHandle = tie $totalDataReceived,  'IPC::Shareable',undef,{destroy =>1}
or die "Could not share variable $!";
$cdHandle = tie $totalDataSent,  'IPC::Shareable',undef,{destroy =>1}
or die "Could not share variable $!";
#######Shared data end


#####Calculating interface for now

#Verify we have proper input. 
sub die_handler
{
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

unless( $devInfo{'host'} )
{
    log_msg("ERROR: Please specify a dev host.");
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

if($transportTTargs{'ctype'} eq 'TLS')
{
    unless ( $ftpInfo{'login'} && $ftpInfo{'pass'} && $ftpInfo{'IP'} )
    {
         log_msg("Specify user name and password for FTP login.");
         exit 1;
    }
    importTLSCertificates($session,\%transportTTargs,\%ftpInfo);
   
}

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

#
# Create five instances of Transport Test Tool this requires  
# five instances of telnet sessions which is done below
#
for($i=0;$i<$instances;$i++)
{
    ####### Set up telnet for all server instances
    #### One telnet was causing serialization
    $devSession[$i] = new Net::Telnet (Timeout=>10,Prompt=>'/\$ $/i');
    if(!defined( $devSession[$i] ) )
    {
        log_msg("ERROR: Can not connect to Remote dev machine $devInfo{'host'}: $!");
        exit 1;
    }
    $devSession[$i]->input_log( *STDOUT );
    $devSession[$i]->open($devInfo{'host'});
    $devSession[$i]->login($devInfo{'user'},$devInfo{'pass'});
    $devSession[$i]->binmode(1);
    my $port = $transportTTargs{'srp'}+$i;
    if($transportTTargs{'ctype'} eq 'TLS')
    {
        $startTTServer = "TransportTT --pra $transportTTargs{'pra'}".
                  " --prp $transportTTargs{'prp'} -l $transportTTargs{'length'}".
                  "  -p $transportTTargs{'ctype'}  -P $transportTTargs{'threads'}".  
                  " -n $transportTTargs{'connection'} -f $transportTTargs{'testfile'}". 
                  " --sra $transportTTargs{'sra'}  --srp $port".  
                  " -s $transportTTargs{'stype'}   --tmo $transportTTargs{'tmo'}  --type 2 -k $transportTTargs{'keyfile'}";

    }
    else
    {
         $startTTServer = "TransportTT --pra $transportTTargs{'pra'}".
                  " --prp $port -l $transportTTargs{'length'}".
                  "  -p $transportTTargs{'ctype'}  -P $transportTTargs{'threads'}".  
                  " -n $transportTTargs{'connection'} -f $transportTTargs{'testfile'}". 
                  " --sra $transportTTargs{'sra'}  --srp $port".  
                  " -s $transportTTargs{'stype'}   --tmo $transportTTargs{'tmo'}  --type 2";
 
    }
    push(@servers,$startTTServer);
}
#
# Client settings for TransportTT
#
# Create five instances of Transport Test Tool Client this requires  
# five instances of telnet sessions to send traffic to the SD
#
for($i=0;$i<$instances;$i++)
{
   if($transportTTargs{'ctype'} eq 'TLS')
   {
        $startTTClient =                        "TransportTT --pra $transportTTargs{'pra'}".
                             " --prp $transportTTargs{'prp'} -l $transportTTargs{'length'}".
                           "  -p $transportTTargs{'ctype'}  -P $transportTTargs{'threads'}".  
                       " -n $transportTTargs{'connection'} -f $transportTTargs{'testfile'}". 
                            " --sra $transportTTargs{'sra'}  --srp $transportTTargs{'srp'}".  
                  " -s $transportTTargs{'stype'}   --tmo $transportTTargs{'tmo'}  --type 1". 
                                                       "-k $transportTTargs{'keyfile'}";

   }
   else
   {
       $startTTClient =                 "TransportTT --pra $transportTTargs{'pra'}".
                  " --prp $transportTTargs{'prp'} -l $transportTTargs{'length'}".
                  "  -p $transportTTargs{'ctype'}  -P $transportTTargs{'threads'}".  
                  " -n $transportTTargs{'connection'} -f $transportTTargs{'testfile'}". 
                  " --sra $transportTTargs{'sra'}  --srp $transportTTargs{'srp'}".  
                  " -s $transportTTargs{'stype'}   --tmo $transportTTargs{'tmo'}  --type 1";
 
   }
   push(@TTClient,$startTTClient);
}
my $connections = $transportTTargs{'connection'} * $transportTTargs{'threads'};

for($i=0;$i<$instances;$i++)
{
    ######setting telnet session for client instances########
    $clientSession[$i] = new Net::Telnet (Timeout=>10,Prompt=>'/\$ $/i');
    if(!defined( $clientSession[$i] ) )
    {
        log_msg("ERROR: Can not connect to Remote dev machine $devInfo{'host'} client session $i: $!");
        exit 1;
    }

    $clientSession[$i]->input_log( *STDOUT );
    $clientSession[$i]->open($devInfo{'host'});
    $clientSession[$i]->login($devInfo{'user'},$devInfo{'pass'});
    $clientSession[$i]->binmode(1);
    
    my $serverPort = $transportTTargs{'srp'}+$i;
    my $clientPort = $transportTTargs{'sdCPort'}+($i*1000);
    if($transportTTargs{'ctype'} eq 'TCP')
    {
        $clientSet =     "transport_test_tcp_client_start ".
                     "\"$transportTTargs{'pra'}\"\, ".
                      "$clientPort, ".
                     "\"$transportTTargs{'sra'}\"\, ".
                          "$serverPort, ".
                "\"$transportTTargs{'cProfile'}\"\, ".
                        "$transportTTargs{'cslot'}, ".
                        "$transportTTargs{'cport'}, ".
                        "$transportTTargs{'cvlan'}, ".
                                       "$connections";
    }
    elsif($transportTTargs{'ctype'} eq 'TLS')
    {
        $clientSet =     "transport_test_tls_client_start ".
                     "\"$transportTTargs{'pra'}\"\, ".
                      "$clientPort, ".
                     "\"$transportTTargs{'sra'}\"\, ".
                          "$serverPort, ".
                "\"$transportTTargs{'cProfile'}\"\, ".
                        "$transportTTargs{'cslot'}, ".
                        "$transportTTargs{'cport'}, ".
                        "$transportTTargs{'cvlan'}, ".
                                       "$connections";
    }
    push(@client,$clientSet);
}
$i=0;

###### Forking for each server instance and 
###### run the command on external server through telnet.
###### Each instance would then wait for the command to finish

foreach my $server (@servers)
{
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
        @resultTT = $devSession[$i]->cmd(String=>"$server",Timeout=>120,Prompt => "/Test Complete/"); 
        foreach(@resultTT)
        {
            
            if(/Unsuccessful/)
            {
                ($temp,$unConnections) = split('\s+\:',$_);
                if($unConnections != 0)
                {
                    log_msg("--------------Test instance Failed:Unsucessful Connections Server-------------");
                    exit(1); 
                }    
            }
            if(/Successful/)
            {
                ($temp,$connections) = split('\s+\:',$_);
                $scHandle->shlock();
                $totalServerConnections += $connections;
                $scHandle->shunlock();
                log_msg("Connections:$connections;totalconnections:$totalServerConnections");
                if($connections == 0)
                {
                    log_msg("--------------Test Instance Failed:No Connections Server------------------------");
                    exit(1); 
                }
            }
            if(/Data/ &&  /received/ && /kbytes/)
            {
                @dReceived = split('\s+\:',$_); 
                ($dReceived,$trash)=split('\s+', $dReceived[1]);
                $dHandle->shlock();
                $totalDataReceived += $dReceived;
                log_msg("Data:$dReceived;total Data:$totalDataReceived");
                $dHandle->shunlock();
                if($dReceived == 0)
                {
                    log_msg("--------------Test Instance Failed:No Data Received------------------------");
                    exit(1); 
                }
            }
        }
        @resultTT = trimArray(@resultTT);
 
        if(grep $_ =~ /Test Failed/i, @resultTT)
        {
            log_msg("-----Server Child Instance Failed-----");
            exit(1);
        }
        else
        {
           log_msg("-----Server Child Instance Passed-----");
           exit(0);     
        }
    }
    $i++;
}    
log_msg("Executing TT: $startTTServer\n");

#######################################END############################
sleep (5);
$session->print ("");
($prematch, $match) = $session->waitfor(Match => "/->|acli-shell:/");
# Start Client on SD

foreach my $client (@client)
{    
    sleep(1);
    my @resultsClient = $session->cmd(String => "$client",Timeout => 20,
                                  Prompt => "/->/" );
}

$i=0;

###### Forking for each server instance and 
###### run the command on external server through telnet.
###### Each instance would then wait for the command to finish

foreach my $TTClient (@TTClient)
{
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
    
        @resultTT = $clientSession[$i]->cmd(String=>"$TTClient",Timeout=>300,Prompt => "/Test Complete/"); 
        foreach(@resultTT)
        {
           
           if(/Unsuccessful/)
            {
                ($temp,$unConnections) = split('\s+\:',$_);
                if($unConnections != 0)
                {
                    log_msg("--------------Test Instance Failed:Unsucessful Connections Server-------------");
                    exit(1); 
                }
                
            }
            if(/Successful/)
            {
                ($temp,$connections) = split('\s+\:',$_);
                $cHandle->shlock();
                $totalConnections += $connections;
                $cHandle->shunlock(); 
                log_msg("Connections:$connections;totalconnections:$totalConnections");
                if($connections == 0)
                {
                    log_msg("--------------Test Instance Failed:No Connections Server------------------------");
                    exit(1); 
                }
            
            }
            if(/Data/ &&  /sent/)
            {
                ($temp,$dSent)=split('\s+\:',$_);
                $cdHandle->shlock();
                $totalDataSent += $dSent;
                log_msg("Data:$dSent;total Data:$totalDataSent");
                $cdHandle->shunlock();
                if($dSent == 0)
                {
                    log_msg("--------------Test Instance Failed:No Data Received------------------------");
                    exit(1); 
                }
            
            }
        }
        @resultTT = trimArray(@resultTT);

        if(grep $_ =~ /Test Failed/i, @resultTT)
        {
            log_msg("-----Client Child Instance Failed-----");
            exit(1);
        }
        else
        {
           log_msg("-----Client Child Instance Passed-----");
           exit(0);     
        }
   }
   $i++
}

foreach(@pids)
{
    
    my $tmp = waitpid($_,0);
    $? = $? >> 8;
    log_msg("Child $tmp finished with results $?");
    $childResults += $?;
}
my $numSuccess = $childResults;

# Check if connections are equal both sides

if($totalServerConnections != $totalConnections)
{
    $numSuccess = 1;
    log_msg("**********Total Connections not equal test Failed***********");    
}
if($totalDataSent != $totalDataReceived)
{
    $numSuccess = 1;
    log_msg("**********Total Data Sent not equal to Data Received********");    
}
####### Stats ############
####Total Server Connections #######
# Stats from all the server instances are printed
# Stats from all the cleint instances are printed

print ("\n");
print ("\n");
log_msg("--------------Transport STATS----------------");
print ("\n");
log_msg("Total Connections Server        :$totalServerConnections");
log_msg("Total Connections client        :$totalConnections");
log_msg("Total Data Received Server      :$totalDataReceived Kbytes");
log_msg("Total Data Sent Client          :$totalDataSent Kbytes");
print ("\n");
log_msg("--------------!!!END STATS!!!----------------");
print ("\n");
print ("\n");

#### Tricky Cavium console stats ####

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
     #get bandwidth an other stats
     log_msg("----------------SD END STATS-----------------");
}

### Cleanup####

my $cleanup = $devSession[0]->print("rm -rf $wildcard");
sleep 1;
my $logCleanup = $devSession[0]->print("rm -rf errorlog.txt");

if(sdGoToAcliPrompt(Session => $session, Name => $sbcInfo{'sdname'}))
{
    log_msg("ERROR: Could not reach Acli prompt.");
    exit 1;
}
#### Very very bad idea for clean up but we do not have a clean way to 'clean up' yet ###

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
    system ( "$ENV{'RESULT_SCRIPT'} -variant 'none' -result 'Fail'" );
    
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
        system ( "$ENV{'RESULT_SCRIPT'} -variant1 'non-zero' -result 'Fail'" );
    }

}



