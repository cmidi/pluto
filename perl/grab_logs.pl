#!/usr/bin/perl

use Time::HiRes qw( usleep );
use Net::Telnet;
use Getopt::Long;
use Cwd;
use Net::FTP;
use Acme::embtestlib;


my($directory, $filename) = Cwd::abs_path($0) =~ m/(.*\/)(.*)$/;
#require "${directory}functions.pl";


#Untaint every input. It is not secure, but we have to do it for now becasue anvil is run with setuid bit
foreach (@ARGV)
{
    $_ =~ m/^(.*)$/ or die "Value is tainted\n";
    $_ = $1;
}

#Untaint every ENV. It is not secure, but we have to do it for now becasue anvil is run with setuid bit
while(($key, $value) = each %ENV)
{
    $ENV{$key} =~ m/^(.*)$/ or die "Value is tainted\n";
    $ENV{$key} = $1;
}

$SIG{__DIE__} = \&die_handler;

# *** NOTE *** If wanting to connect via the console connection, precede the port # with 20

#########################
# Config (defaults)
$userpass = "acme";
$enablepass = "packet";
$vxworkspass = "vxworks";
$port = 0;
$newErr = 0;
$ramdrv = "\"\/ramdrv\/\"";
$code = "\"\/code\/\"";
#ftp doesn't use the quotes
$ftpramdrv = "\/ramdrv\/";
$ftpcode = "\/code\/";
$continue = 0;
$suitename = "";
$logsDir = "";
$tarVerified = 0;
$dumpetc = "dump-etc-all\.xz";
$taskCheck = "taskCheckDump\.dat";
$npstats = "npstats\.dump";


%sbcInfo = ( 'sbcConfig' => "",
             'sdname'    => "",
             'host'      => "",
	         'port'      => 23 );

%ftpInfo = ( 'login' => "",
	     'pass'  => "",
	     'IP'    => "", ); 

GetOptions( "host=s"       => \$sbcInfo{'host'},
	        "port=i"       => \$sbcInfo{'port'},
	        "sdname=s"     => \$sbcInfo{'sdname'},
	        "suitename=s"  => \$suitename,
	        "logsdir=s"    => \$logsDir,	   
	        "ftplogin=s"   => \$ftpInfo{'login'},
	        "ftppass=s"    => \$ftpInfo{'pass'},
	        "ftpip=s"     => \$ftpInfo{'IP'} );
      

##########################

# Stop the script if the directory is not specified or if the login/pass
# are not specified.
unless( $suitename )
{
    log_msg("Specify suite name.");
    instructions();
    exit 1;
}

unless ( $ftpInfo{'login'} && $ftpInfo{'pass'} && $ftpInfo{'IP'} )
{
    log_msg("Specify user name and password for FTP login.");
    instructions();
    exit 1;
}

unless( $sbcInfo{'host'} )
{
    log_msg("Please specify a host(console server ip)");
    instructions();
    exit 1;
}

unless( $logsDir )
{
    log_msg("Specify logs directory.");
    instructions();
    exit 1;
}
#############################

#Begin Telnet, log into SD.

my $session = Net::Telnet->new( Host => $sbcInfo{'host'}, Port => $sbcInfo{'port'} );
$session->input_log( *STDOUT );

if ( not defined( $session ) )
{
    log_msg("Can't connect to SD HOST $sbcInfo{'host'}: $!");
    exit 1;
}

log_msg("\nConnected to the console server. Starting script...");

#Ensure we are at the inital password command prompt 
#(may need to revisit, but seems quicker than before)
if( sdGoToShellPrompt( $session, $sbcInfo{'sdname'} ) )
{
    log_msg("ERROR: Could not reach 'Password:' prompt.");
    exit 1;
}

#Create a .tar of the logs in /ramdrv/ with the name of the suite

$session->print( "tarArchive \"\/ramdrv\/$suitename\.tar\"\, 512\, 1\, \"\/ramdrv\/logs\"");

#Check if we've created it properly.

( $prematch, $match ) = $session->waitfor( Match => "/->|acli-shell:/" );

#ls and verify the .tar
@results = $session->cmd( String => "ls ${ramdrv}", Timeout => 10, Prompt=> "/->|acli-shell:/");

foreach(@results){
	chomp($_);
#	log_msg($_);

	if( /$suitename/ ){
	    $tarVerified = 1;
	}
}


if($tarVerified){
    log_msg("Tar file $suitename\.tar has been created successfully.");
}
else{
    log_msg("Error: Tar file creation could not be verified.");
    log_msg("Aborting script.");
    valuelist();
    exit 1;    
}

############################
#Check which logs are present in /code/

$session->print("cd $code");

( $prematch, $match ) = $session->waitfor( Match => "/->|acli-shell:/" );


@results = $session->cmd( String=> "ls", Timeout => 10, Prompt => "/value/" );

$logNpstats_present = 0;
$logTaskCheck_present = 0;
$logETC_present = 0;

foreach(@results){
    chomp($_);
#   log_msg($_);
    if( /npstats\.dump\s/ ){
        log_msg("LOG: npstats.dump present. Preparing to get file.");
	$logNpstats_present = 1;
    }

    if( /taskCheckDump\.dat\s/ ){
        log_msg("LOG: taskCheckDump.dat present. Preparing to get file.");
	$logTaskCheck_present = 1;
    }
    if( /\bdump-etc-all\.xz\b/ ){
	log_msg("LOG: dump-etc-all.xz present. Preparing to get file.");
	$logETC_present = 1;
    }
}
#Let us know if the logs aren't there.
if(!$logNpstats_present){
    log_msg("LOG: npstats.dump is not present.");
}
if(!$logTaskCheck_present){
log_msg("LOG: taskCheckDump.dat is not present.");
}
if(!$logETC_present){
    log_msg("LOG: dump-etc-all.xz is not present.");
}

#############################

#Begin FTP steps.

##############################

#Log into the FTP.

my $ftp = Net::FTP->new($ftpInfo{'IP'});
if ( not defined( $ftp ) )
{
    log_msg("Can't connect to SD FTP $ftpInfo{'IP'}, $!");
    exit 1;
}
$ftp->binary();

$ftp->login($ftpInfo{'login'}, $ftpInfo{'pass'}) or $newErr=1;
log_msg("FTP Error: Cannot log in.") if $newErr;
valuelist() if $newErr;
$ftp->quit if $newErr;
exit 1 if $newErr;

############################


############################

#Change to /ramdrv/

$ftp->cwd($ftpramdrv) or $newErr=1;
log_msg("FTP Error: Can't Cd into dir $ftpramdrv") if $newErr;
valuelist() if $newErr;
$ftp->quit if $newErr;
exit 1 if $newErr;
log_msg("Changed to $ftpramdrv.");

###########################
#Check for directory, create if it's not there.

unless (-d "$logsDir\/$suitename")
{
    mkdir("$logsDir\/$suitename");
    log_msg("Creating folder: $logsDir\/$suitename");
}

##########################

#Get $suitename.tar

$ftp->get("$suitename\.tar", "$logsDir\/$suitename\/$suitename\.tar") or $newErr=1;
log_msg("FTP Error: Failed to get file $suitename.tar.") if $newErr;
valuelist() if $newErr;
$ftp->quit if $newErr;
exit 1 if $newErr;
log_msg("Got file $suitename.tar.");
log_msg("Put file in $logsDir\/$suitename.");


#########################
#cd into /code/

$ftp->cwd($ftpcode) or $newErr=1;
log_msg("FTP Error: Can't Cd into dir $ftpcode") if $newErr;
valuelist() if $newErr;
$ftp->quit if $newErr;
exit 1 if $newErr;
log_msg("Changed to $ftpcode.");



#########################
#Get: dump-etc-all.xz 
if($logETC_present){

    $ftp->get("$dumpetc", "$logsDir\/$suitename\/$dumpetc") or $newErr=1;
    log_msg("FTP Error: Failed to get file $dumpetc.") if $newErr;
    valuelist() if $newErr;
    $ftp->quit if $newErr;
    exit 1 if $newErr;
    log_msg("Got file $dumpetc.");
    log_msg("Put file in $logsDir\/$suitename.");
}

#########################
#Get: npstats.dump

if($logNpstats_present){

    $ftp->get("$npstats", "$logsDir\/$suitename\/$npstats") or $newErr=1;
    log_msg("FTP Error: Failed to get file $npstats.") if $newErr;
    valuelist() if $newErr;
    $ftp->quit if $newErr;
    exit 1 if $newErr;
    log_msg("Got file $npstats.");
    log_msg("Put file in $logsDir\/$suitename.");
}

#########################
#Get: taskCheckDump.dat

if($logTaskCheck_present){

    $ftp->get("$taskCheck", "$logsDir\/$suitename\/$taskCheck") or $newErr=1;
    log_msg("FTP Error: Failed to get file $taskCheck.") if $newErr;
    valuelist() if $newErr;
    $ftp->quit if $newErr;
    exit 1 if $newErr;
    log_msg("Got file $taskCheck.");
    log_msg("Put file in $logsDir\/$suitename.");
}

#Done with FTP
$ftp->quit;

#########################
#Remove logs

$session->print("cd $code");

($prematch, $match) = $session->waitfor( Match => "/->/" );

#Remove log file: npstats.dump
sleep(1);

$session->print( "rm \"npstats\.dump\"" );

($prematch, $match) = $session->waitfor( Match => "/->/" );


#Remove log file: taskCheckDump.dat
sleep(1);
$session->print( "rm \"taskCheckDump\.dat\"" );

($prematch, $match) = $session->waitfor( Match => "/->/" );

#Remove log file: dump-etc-all.xz
if($logETC_present){
    sleep(1);

    $session->print( "rm \"dump-etc-all\.xz\"" );

    ($prematch, $match) = $session->waitfor( Match => "/->/" );

}
#Check if logs were removed.

$session->buffer_empty;
$session->print("");

($prematch, $match) = $session->waitfor( Match => "/->/" );

@results = $session->cmd( String=> "ls", Timeout => 10, Prompt => "/->|acli-shell:/" );
sleep(1);

$logNpstats_removed = 1;
$logTaskCheck_removed = 1;
$logETC_removed = 1;

foreach(@results){
    
    chomp($_);
#   log_msg($_);
    
    if( /npstats\.dump\s/ ){
	log_msg("LOG:Error: npstats.dump has not been removed.");
	$logNpstats_removed = 0;
    }
    
    if( /taskCheckDump\.dat\s/ ){
        log_msg("LOG:Error: taskCheckDump.dat has not been removed.");
        $logTaskCheck_removed = 0;
    }
    if($logETC_present){
	if( /\bdump-etc-all\.xz\b/ ){
	    log_msg("LOG:Error: dump-etc-all.xz has not been removed..");
	    $logETC_removed = 0;
	}
    }
}


#Let us know if the logs were removed.
if($logNpstats_removed){
    log_msg("LOG: npstats.dump removed.");
}
if($logTaskCheck_removed){
    log_msg("LOG: taskCheckDump.dat removed.");
}
if($logETC_present && $logETC_removed){
    log_msg("LOG: dump-etc-all.xz removed.");
}

#Unzip the .tar
$untarPath = "logs\/$suitename";

system("tar -xvf $logsDir\/$suitename\/$suitename\.tar -C $untarPath");

valuelist();

log_msg("End of script. Exiting..");

exit 1;

sub valuelist {
    log_msg("------What's in each variable---------");
    log_msg("Host:               $sbcInfo{'host'}");
    log_msg("Port:               $sbcInfo{'port'}");
    log_msg("Suite Name:         $suitename");
    log_msg("Ftp Login:          $ftpInfo{'login'}");
    log_msg("Ftp Pass:           $ftpInfo{'pass'}");
    log_msg("Ftp IP:             $ftpInfo{'IP'}");
    log_msg("Tar verified(t/f):  $tarVerified");
    log_msg("logsDir:            $logsDir");
    log_msg("untarPath:          $untarPath");
    log_msg("------Check if logs are present-t/f---");
    log_msg("dump-etc-all.xz:    $logETC_present");
    log_msg("npstats.dump:       $logNpstats_present");   
    log_msg("taskCheckDump.dat:  $logTaskCheck_present");
    log_msg("----Check if logs were removed-t/f----"); 
    log_msg("Note: if ETC was not detected, the log will not be removed.");
    log_msg("dump-etc-all.xz:    $logETC_removed");
    log_msg("npstats.dump:       $logNpstats_removed");
    log_msg("taskCheckDump.dat:  $logTaskCheck_removed");
}

sub instructions{

    log_msg("Calling usage: -host -port -suitename -logsdir -ftplogin -ftppass -ftpip");
    log_msg("Note: logsDir requires full path. Ex: \/home\/name\/etc\/etc.");
}
