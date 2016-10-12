# Written by Scott McCulley

package Acme::embtestlib;

use strict;
use warnings;
use Exporter;
use Net::Telnet;
use Switch;

our @ISA = qw( Exporter );

# these can be exported.
our @EXPORT_OK = qw( get_timestamp tclListToHash parseTestInfo checkSystemResults log_msg sdGoToPasswordPrompt sdGoToAcliPrompt sdGoToShellPrompt parseReturnValue trimString trimArray surroundWithQuotes ROOT LOGS );

# these are exported by default
our @EXPORT = qw( get_timestamp parseTestInfo checkSystemResults log_msg sdGoToPasswordPrompt sdGoToAcliPrompt sdGoToShellPrompt sdGoToLinuxPrompt parseReturnValue trimString trimArray surroundWithQuotes ROOT LOGS dump_log untaint_ARGV_ENV is_v6 parse_sdl_results parse_nat_results print_nat_hash resolve_L2);


use constant
{
    ROOT    => "/home/embtest/embtest/",
    LOGS    => "/home/embtest/embtest/logs/",
    USERPASS => "acme",
    ENABLEPASS => "packet",
    VXWORKSPASS => "vxworks",
    MAX_RETRY_COUNT => 20
};

sub get_timestamp()
{
    (my $sec, my $min, my $hour, my $mday, my $mon, my $year, my $wday, my $yday, my $isdst) = localtime(time);

    if ($mon < 10) { $mon = "0$mon"; }
    if ($hour < 10) { $hour = "0$hour"; }
    if ($min < 10) { $min = "0$min"; }
    if ($sec < 10) { $sec = "0$sec"; }
    $year=$year+1900; 

    return $mon+1 . '/' . $mday . '/' . $year . " " . $hour . ':' . $min . ':' . $sec;
}

sub tclListToHash($)
{
    my $list = shift;
    $list =~ s/^{|}$//g;

    my %hash;

    my @temp = split /} {/, $list;
    foreach(@temp)
    {
        (my $key,my $value) = split(' ', $_, 2);
        $hash{$key} = $value;
    }

    return %hash;
}

sub parseTestInfo($)
{
    my $list = shift;
    my %hash = tclListToHash($list);
    
    $hash{"NOTES"} =~ s/^{|}$//g;
    $hash{"TESTSUITE"} =~ s/^{|}$//g;
    $hash{"TESTSUITE"} = [split(' ', $hash{"TESTSUITE"})];
    foreach(@{$hash{"TESTSUITE"}})
    {
        if($hash{"SUBTEST:$_"})
        {
            $hash{"SUBTEST:$_"} =~ s/^{|}$//g;
            $hash{"SUBTEST:$_"} = [split(' ', $hash{"SUBTEST:$_"})];
        }
    }

    return %hash;
}

sub checkSystemResults($)
{
    my $results   = shift;
    my $returnVal = "";

    if($results == -1)
    {
        $returnVal = "Failed to execute: $results";
    }
    elsif($results & 127)
    {
        $returnVal = "Child died with signal: " . ($results & 127); 
        # . ", " . ($results & 127), ($results & 128) ? 'with' : 'without' . "coredump";
    }
    else
    {
        $returnVal = "Child exited with value: " . ($results >> 8);
    }

    return $returnVal;
}

sub log_msg(@)
{
    my $message = $_[0];
    my $prefix  = $_[1];

    unless($prefix)
    {
        $prefix = "INFO";
    }

    print get_timestamp() . " ${prefix}: $message\n";
}

sub sdGoToPasswordPrompt
{
    my $telnet   = undef;
    my $sdname   = "";
    my $regex    = "";
    my $match    = "";
    my $prematch = "";
    my $argument = "";

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?session$/i)
            {
                $telnet = $argument;
            }
            elsif(/^-?name$/i)
            {
                $sdname = $argument;
            }
        }
    }

    if(!defined($telnet) | $sdname eq "")
    {
        log_msg("Please provide both Session and Name of DUT");
        return 1;
    }

    $regex = "/${sdname}>|${sdname}#|\->|Password:|\Qy/n\E|\Q)#\E|space bar|${sdname}\@0.0.0>|${sdname}\@0.0.0#/";

    my $retryCount = 0;

    $telnet->print("");

    while($retryCount < MAX_RETRY_COUNT)
    {
        ( $prematch, $match ) = $telnet->waitfor( Match => $regex,
                                                  Timeout => 1,
                                                  Errmode => "return" );
        $retryCount++;

        print("\n");

        if($telnet->errmsg ne "")
        {
            log_msg("Could not match anything, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
            $telnet->print("");
        }
        else
        {
            switch($match)
            {
                case /${sdname}>/
                {
                    log_msg("Matched ${sdname}>, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("exit");
                }
                case /${sdname}#/
                {
                    log_msg("Matched ${sdname}#, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("exit");
                }
                case /->/
                {
                    log_msg("Matched ->, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("exit");
                }
                case /acli-shell:/
                {
                    log_msg("Matched acli-shell, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("exit");
                }
                case /y\/n/
                {
                    log_msg("Matched y/n prompt, saying n, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("n");
                }
                case /Password:/
                {
                    log_msg("#### Arrived at Password: ####", "NAV");
                    return 0;
                }
                case /\)\#/
                {
                    log_msg("Matched )#\n");
                    $telnet->print("exit");
                }
                case/${sdname}\@0.0.0>/
                {
                    log_msg("Matched ${sdname}\@0.0.0>, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("exit");
                }
                case/${sdname}\@0.0.0#/
                {
                    log_msg("Matched ${sdname}\@0.0.0#, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("exit");
                }
                else
                {
                    log_msg("Hit default case, printing \"\", retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("");
                }
            }
        }

        $telnet->buffer_empty;
    }

    print("\nExceeded maximum retry count\n");

    return 1;
}

sub sdGoToAcliPrompt
{
    my $telnet      = undef;
    my $sdname      = "";
    my $regex       = "";
    my $match       = "";
    my $prematch    = "";
    my $retryCount  = 0;
    my $argument    = "";
    my $retry_count = MAX_RETRY_COUNT; 

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?session$/i)
            {
                $telnet = $argument;
            }
            elsif(/^-?name$/i)
            {
                $sdname = $argument;
            }
            elsif(/^-?retry$/i)
            {
                $retry_count = $argument;
            }
        }
    }

    if(!defined($telnet) | $sdname eq "")
    {
        log_msg("Please provide both Session and Name of DUT");
        return 1;
    }

    my $linuxPrompt = "\Q/\E";
    log_msg ("$linuxPrompt");
    $regex = "/${sdname}>|${sdname}#|\->|Password:|\Qy/n\E|\Q)#\E|\Q~ #\E|${linuxPrompt}|space bar|${sdname}\@\0.0.0>|${sdname}\@\0.0.0#/";

    print("\n");
    log_msg("Navigating to \"#\", acli", "NAV");

    $telnet->print("");

    while($retryCount < $retry_count)
    {
        ( $prematch, $match ) = $telnet->waitfor( Match => $regex,
                                                  Timeout => 1,
                                                  Errmode => "return" );
        $retryCount++;
        print("\n");

        if($telnet->errmsg ne "")
        {
            log_msg("Could not match anything, retry count: ${retryCount}/" . $retry_count);
            $telnet->print("");
        }
        else
        {
            switch($match)
            {
                
                case /${sdname}>/
                {
                    log_msg("Matched ${sdname}>, retry count: ${retryCount}/" . $retry_count);
                    $telnet->print("en");
                    ( $prematch, $match ) = $telnet->waitfor(String => "Password:");
                    $telnet->print(ENABLEPASS);
                }
                case /${sdname}#/
                {
                    log_msg("#### Arrived ${sdname}# ####", "NAV");
                    return 0;
                }
                case /->/
                {
                    log_msg("Matched ->, retry count: ${retryCount}/" . $retry_count);
                    $telnet->print("exit");
                }
                case /acli-shell:/
                {
                    log_msg("Matched acli-shell, retry count: ${retryCount}/" . $retry_count);
                    $telnet->print("exit");
                }
                case /y\/n/
                {
                    log_msg("Matched y/n, saying n, retry count: ${retryCount}/" . $retry_count);
                    $telnet->print("n");
                }
                case /Password:/
                {
                    log_msg("Matched Password:, retry count: ${retryCount}/" . $retry_count);
                    $telnet->print(USERPASS);
                }
                case /\)\#/
                {
                    log_msg("Matched )#\n");
                    $telnet->print("exit");
                }
                case/${sdname}\@0.0.0>/
                {
                    log_msg("Matched ${sdname}\@0.0.0>, retry count: ${retryCount}/" . $retry_count);
                    $telnet->print("en");
                    ( $prematch, $match ) = $telnet->waitfor( String => "Password:" );
                    $telnet->print(ENABLEPASS);

                }
                case/${sdname}\@0.0.0#/
                {
                    log_msg("#### Arrvied at ${sdname}\@0.0.0# ####", "NAV");
                    return 0;
                }
                case/\Q~ #\E/
		       {
                    log_msg("Matched linux prompt");
                    $telnet->print("exit");
                }
                case/${linuxPrompt}/
		       {
                     log_msg("Matched linux prompt");
                    $telnet->print("exit");
                }
                else
               
               {
                    log_msg("Hit default case, printing \"\", retry count: ${retryCount}/" . $retry_count);
                    $telnet->print("");
		    
                }
            }
        }

        $telnet->buffer_empty;
    }

    print("\nExceeded maximum retry count\n");

    return 1;
}

sub sdGoToShellPrompt
{
    my $telnet      = undef;
    my $sdname      = "";
    my $regex       = "";
    my $match       = "";
    my $prematch    = "";
    my $retryCount  = 0;
    my $argument    = "";
    my $shellPrompt = "";

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?session$/i)
            {
                $telnet = $argument;
            }
            elsif(/^-?name$/i)
            {
                $sdname = $argument;
            }
        }
    }

    if(!defined($telnet) | $sdname eq "")
    {
        log_msg("Please provide both Session and Name of DUT");
        return 1;
    }
     my $linuxPrompt = "\Q/\E";
     $regex = "/${sdname}>|${sdname}#|\->|Password:|\Qy/n\E|\Q)#\E|\Q~ #\E|${linuxPrompt}|space bar|${sdname}\@\0.0.0>|${sdname}\@\0.0.0#/";
         
    print("\n");
    log_msg("Navigating to \"->\", shell/control shell", "NAV");

    $telnet->print("");

    while($retryCount < MAX_RETRY_COUNT)
    {
        ( $prematch, $match ) = $telnet->waitfor( Match   => $regex,
                                                  Timeout => 1,
                                                  Errmode => "return" );
        $retryCount++;

        print("\n");

        if($telnet->errmsg ne "")
        {
            log_msg("Could not match anything, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
            print "Error: " . $telnet->errmsg . "\n";
            $telnet->print("");
        }
        else
        {
            switch($match)
            {
                case /${sdname}>/
                {
                    log_msg("Matched ${sdname}>, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("en");
                    ( $prematch, $match ) = $telnet->waitfor(String => "Password:");
                    $telnet->print(ENABLEPASS);
                }
                case /${sdname}#/
                {
                    log_msg("Matched ${sdname}#, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $shellPrompt = $telnet->cmd(String => "control",Timeout => 5,Prompt => "/Password:|% command not found/");
                    if($shellPrompt eq "Password:")
                    {
                        $telnet->print(VXWORKSPASS);
                        log_msg("Entered control Shell");
                    }
                    else
                    {
                        $telnet->print("shell");
                        ( $prematch, $match ) = $telnet->waitfor( String => "Password:" );
                        $telnet->print(VXWORKSPASS);
                        log_msg("Entered vxworks Shell");
                    }
                    
                }
                case /->/
                {
                    log_msg("#### Arrived at -> ####", "NAV");
                    return 0;
                }
                case /acli-shell:/
                {
                    log_msg("#### Arrived at acli-shell ####", "NAV");
                    return 0;
                }
                case /y\/n/
                {
                    log_msg("Matched y/n prompt, saying n, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("n");
                }
                case /Password:/
                {
                    log_msg("Matched Password: prompt, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print(USERPASS);
                    ( $prematch, $match ) = $telnet->waitfor( String => "Password:",
                                                              Timeout => 1,
                                                              Errmode => "return" );
                    if($telnet->errmsg eq "")
                    {
                        $telnet->print(ENABLEPASS);
                        ( $prematch, $match ) = $telnet->waitfor( String => "Password:",
                                                                  Timeout => 1,
                                                                  Errmode => "return" );

                        if($telnet->errmsg eq "")
                        {
                            $telnet->print(VXWORKSPASS);
                        }
                    }

                }
                case /\)\#/
                {
                    log_msg("Matched )#\n");
                    $telnet->print("exit");
                }
                case/${sdname}\@0.0.0>/
                {
                    log_msg("Matched ${sdname}\@0.0.0>, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("en");
                    ( $prematch, $match ) = $telnet->waitfor( String => "Password:" );
                    $telnet->print(ENABLEPASS);

                }
                case/${sdname}\@0.0.0#/
                {
                    log_msg("Matched ${sdname}\@0.0.0#, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $shellPrompt = $telnet->cmd(String => "control",Timeout => 5,Prompt => "/Password:|% command not found/");
                    if($shellPrompt eq "Password:")
                    {
                        $telnet->print(VXWORKSPASS);
                    }
                    else
                    {
                        $telnet->print("shell");
                        ( $prematch, $match ) = $telnet->waitfor( String => "Password:" );
                        $telnet->print(VXWORKSPASS);
                    }
	       	}
                case/\Q~ #\E/
		        {
                    log_msg("Matched linux prompt");
                    $telnet->print("exit");
                }
                case/${linuxPrompt}/
	 	       {
                    log_msg("Matched linux prompt");
                    $telnet->print("exit");
                }
                else
                {
                    log_msg("Hit default case, printing \"\", retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("");
                }
            }
        }

        $telnet->buffer_empty;
    }

    print("\nExceeded maximum retry count\n");

    return 1;
}
sub sdGoToLinuxPrompt
{
    my $telnet      = undef;
    my $sdname      = "";
    my $regex       = "";
    my $match       = "";
    my $prematch    = "";
    my $retryCount  = 0;
    my $argument    = "";
    my $shellPrompt = "";

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?session$/i)
            {
                $telnet = $argument;
            }
            elsif(/^-?name$/i)
            {
                $sdname = $argument;
            }
        }
    }

    if(!defined($telnet) | $sdname eq "")
    {
        log_msg("Please provide both Session and Name of DUT");
        return 1;
    }

    my $linuxPrompt = "\Q/\E";
    $regex = "/${sdname}>|${sdname}#|\->|Password:|\Qy/n\E|\Q)#\E|\Q~ #\E|${linuxPrompt}|space bar|${sdname}\@\0.0.0>|${sdname}\@\0.0.0#/";

    print("\n");
    log_msg("Navigating to \"~ #\", Linux shell", "NAV");
    
    $telnet->print("");

    while($retryCount < MAX_RETRY_COUNT)
    {
        ( $prematch, $match ) = $telnet->waitfor( Match => $regex,
                                                  Timeout => 1,
                                                  Errmode => "return" );
        $retryCount++;

        print("\n");

        if($telnet->errmsg ne "")
        {
            log_msg("Could not match anything, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
            $telnet->print("");
        }
        else
        {
            switch($match)
            {
                case /${sdname}>/
                {
                    log_msg("Matched ${sdname}>, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("en");
                    ( $prematch, $match ) = $telnet->waitfor(String => "Password:");
                    $telnet->print(ENABLEPASS);
                }
                case /${sdname}#/
                {
                    log_msg("Matched ${sdname}#, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                        $telnet->print("shell");
                        ( $prematch, $match ) = $telnet->waitfor( String => "Password:" );
                        $telnet->print(VXWORKSPASS);
                        log_msg("Entered Linux  Shell");
                  
                    
                }
                case /->/
                {
                   log_msg("Matched control shell prompt");
                    $telnet->print("exit");
                }
                case /y\/n/
                {
                    log_msg("Matched y/n prompt, saying n, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("n");
                }
                case /Password:/
                {
                    log_msg("Matched Password: prompt, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print(USERPASS);
                    ( $prematch, $match ) = $telnet->waitfor( String => "Password:",
                                                              Timeout => 1,
                                                              Errmode => "return" );
                    if($telnet->errmsg eq "")
                    {
                        $telnet->print(ENABLEPASS);
                        ( $prematch, $match ) = $telnet->waitfor( String => "Password:",
                                                                  Timeout => 1,
                                                                  Errmode => "return" );

                        if($telnet->errmsg eq "")
                        {
                            $telnet->print(VXWORKSPASS);
                        }
                    }

                }
                case /\)\#/
                {
                    log_msg("Matched )#\n");
                    $telnet->print("exit");
                }
                case/${sdname}\@0.0.0>/
                {
                    log_msg("Matched ${sdname}\@0.0.0>, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("en");
                    ( $prematch, $match ) = $telnet->waitfor( String => "Password:" );
                    $telnet->print(ENABLEPASS);

                }
                case/${sdname}\@0.0.0#/
                {
                    log_msg("Matched ${sdname}\@0.0.0#, retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $shellPrompt = $telnet->cmd(String => "control",Timeout => 5,Prompt => "/Password:|% command not found/");
                    if($shellPrompt eq "Password:")
                    {
                        $telnet->print(VXWORKSPASS);
                    }
                    else
                    {
                        $telnet->print("shell");
                        ( $prematch, $match ) = $telnet->waitfor( String => "Password:" );
                        $telnet->print(VXWORKSPASS);
                    }
	       	}
                case/${linuxPrompt}/
		{
                    log_msg("#### Arrived at Linux Shell ####", "NAV");
                    return 0;                   
                }
                case/\Q~ #\E/
		{
                    log_msg("Matched linux prompt");
                    return 0;
                }
                else
                {
                    log_msg("Hit default case, printing \"\", retry count: ${retryCount}/" . MAX_RETRY_COUNT);
                    $telnet->print("");
                }
            }
        }

        $telnet->buffer_empty;
    }

    print("\nExceeded maximum retry count\n");

    return 1;
}


sub trimString( $ )
{
    my $string = shift;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    return $string;
}

sub trimArray( @ )
{
    my @array = @_;

    foreach( @array )
    {
        $_ = trimString( $_ );
    }

    return @array;
}

sub parseReturnValue( @ )
{
    my @tempArray = ();
    my $result    = "";

    foreach( @_ )
    {
        log_msg("Checking: $_");

        @tempArray = split( " = ", $_ );
        my $arraySize = scalar(@tempArray);

        if($arraySize > 1)
        {
            if( $tempArray[0] =~ /^\s*value\s*$|\s*{ value\s*/ )
            {
                $tempArray[1] =~ s/\(.*\)//;
                $result = trimString( $tempArray[1] );
                last;
            }
        }
    }

    return $result;
}

sub surroundWithQuotes($)
{
    my $string = shift;

    if($string !~ /^\"/)
    {
        $string = "\"" . $string;
    }

    if($string !~ /\"$/)
    {
        $string = $string . "\"" ;
    }

    return $string;
}

sub dump_log
{
    my $telnet   = undef;
    my $argument = "";
    my $sdname   = "";
    my $prematch = "";
    my $match    = "";

    if((@_ > 0) && ((@_ % 2) == 0))
    {
        while(($_, $argument) = splice(@_, 0, 2))
        {
            if(/^-?session$/i)
            {
                $telnet = $argument;
            }
            elsif(/^-?name$/i)
            {
                $sdname = $argument;
            }
        }
    }

    if(!defined($telnet) | $sdname eq "")
    {
        log_msg("Please provide both Session and Name of DUT");
        return 1;
    }

    if(sdGoToLinuxPrompt(Session => $telnet, Name => $sdname))
    {
        log_msg("Dump Log ERROR: Could not reach linux prompt.");
        return 1;
    }
    
    print("\n*****************************************************************************\n");
    print("************************ BEGINNING DUMP log.octCtrl *************************\n");
    print("*****************************************************************************\n");
    
    $telnet->print("tail -n 20 /opt/logs/log.octCtrl");
    ($prematch, $match) = $telnet->waitfor(String => "~ #", Timeout => 10);
    
    print("------------------------- ENDING DUMP log.octCtrl ---------------------------\n");
    
    print("\n*****************************************************************************\n");
    print("************************ BEGINNING DUMP log.octData *************************\n");
    print("*****************************************************************************\n");
    
    $telnet->print("tail -n 20 /opt/logs/log.octData");
    ($prematch, $match) = $telnet->waitfor(String => "~ #", Timeout => 10);

    print("------------------------- ENDING DUMP log.octData ---------------------------\n");

    return 0;
}

sub untaint_ARGV_ENV(@){

    my $key;
    my $value;

    #Print running options for test case
    log_msg("$0 @ARGV\n");

    #Untaint every input. It is not secure, but we have to do it for now becasue anvil is run with setuid bit
    foreach (@ARGV) {

        $_ =~ m/^(.*)$/ or die "ARG: Value is tainted:$_\n";
        $_ = $1;
    }

    #Untaint every ENV. It is not secure, but we have to do it for now becasue anvil is run with setuid bit
    while(($key, $value) = each %ENV)
    {
        $ENV{$key} =~ m/^(.*)/ or die "ENV: Value is tainted:$ENV{$key}\n";
        $ENV{$key} = $1;
    }
}

#Use the regexp from Regexp module to check if an address is v6 or not.

sub is_v6(@)
{
    if($_[0] =~ /(?-xism::(?::[0-9a-fA-F]{1,4}){0,5}(?:(?::[0-9a-fA-F]{1,4}){1,2}|:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}|:)|(?::(?:[0-9a-fA-F]{1,4})?|(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})?|))|(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[0-9a-fA-F]{1,4}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){0,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,2}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,3}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,4}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:)))/ )
    {
        return 1;
    }
    else{
        return 0;
    }
}

#Takes SD Listener results and turns them into variables. Returns hash. Hurray
sub parse_sdl_results
{
    my    @output = @_;
    my    %sdl_results = ();

    print "\n";
#    log_msg( "Reading sd_listener results." );

    foreach( @output )
    {
        if( /^SD\sListener\s*:\s*(Success|Fail)\s*$/ ){
            $sdl_results{'result'} = $1;
        }
        elsif( /^Replay\spcap\snum\spkts\s*:\s*(\d+)\s*$/ )
        {
            $sdl_results{'replayNumPkts'} = int( $1 );
        }
        elsif( /^Replay\spkts\stx\s*:\s*(\d+)\s*$/ )
        {
            $sdl_results{'replayTx'} = int( $1 );
        }
        elsif( /^Listen\spcap\snum\spkts\s*:\s*(\d+)\s*$/ )
        {
            $sdl_results{'listenNumPkts'} = int( $1 );
        }
        elsif( /^Listen\sexpected\spkts\srx\s*:\s*(\d+)\s*$/ )
        {
            $sdl_results{'listenExpectedPktsRx'} = int( $1 );
        }
        elsif( /^Listen\sunknown\spkts\srx\s*:\s*(\d+)\s*$/ )
        {
            $sdl_results{'listenUnknownPktsRx'} = int( $1 );
        }
        elsif( /^Listen\sARP\'s\srx\s*:\s*(\d+)\s*$/ )
        {
            $sdl_results{'listenArpRx'} = int( $1 );
        }
        elsif( /^Listen\sARP\'s\stx\s*:\s*(\d+)\s*$/ )
        {
            $sdl_results{'listenArpTx'} = int( $1 );
        }
        elsif( /^Listen\sICMPv6\'s\srx\s*:\s*(\d+)\s*$/ )
        {
            $sdl_results{'listenArpV6Rx'} = int( $1 );
        }
        elsif( /^Listen\sICMPv6\'s\stx\s*:\s*(\d+)\s*$/ )
        {
            $sdl_results{'listenArpV6Tx'} = int( $1 );
        }
        else
        {
            if( $_ ne ""){
                s/\n//g;
                log_msg( "Line Ignored: \'$_\'" );
            }
        }
    }
    log_msg( "Finished parsing sd_listener results.\n" );
    
    return %sdl_results;
    
}

sub parse_nat_results
{
    my @output  = @_;
    my %showNat = ();
    
    print "\n";
    log_msg( "Reading show nat by-index results." );
    
    foreach( @output )
    {
        chomp($_);
        if( /Total\snumber\sof\sentries\sin\sthe\sDatabase\s*\=\s(\d+)\s*$/ ){
            $showNat{'total_entries'} = int($1);
        }
        elsif( /^NAT\stable\ssearch\saddress\s*(\d+),\sxsmAddr\s*(\d+)\s:\s*$/ ){
            $showNat{'nat_id'}   = int($1);
            $showNat{'xsm_addr'} = int($2);
        }
        elsif( /^Maximum\snumber\sof\sentries\sin\sthe\sDatabase\s\=\s(\d+)\s*$/ )
        {
            $showNat{'max_entries'} = int($1);
        }
        elsif( /^Flow\stype:\sFully\squalified\sflow\s*$/ )
        {
            (my $trash, $showNat{'flow_type'}) = split(/:\s/)
        }
        elsif( /^SA_flow_key\s*:/ && /SA_prefix\s:\s(\d+)\s*$/ )
        {
            $_ =~ s/\s//g;
            (my $trash, my $temp) = split( /SA_flow_key:/, $_ );
            ($showNat{'SA_flow_key'}, $showNat{'SA_prefix'}) = split(/SA_prefix:/, $temp);
        }
        elsif( /^DA_flow_key\s*:/ && /DA_prefix\s:\s(\d+)\s*$/ )
        {
            $_ =~ s/\s//g;
            (my $trash, my $temp) = split( /DA_flow_key:/, $_ );
            ($showNat{'DA_flow_key'}, $showNat{'DA_prefix'}) = split(/DA_prefix:/, $temp);
        }
        elsif( /^SP_flow_key\s*:\s(\d+)\s*SP_prefix\s:\s(\d+)\s*$/ )
        {
            $showNat{'SP_flow_key'} = int($1);
            $showNat{'SP_prefix'}   = int($2);
        }
        elsif( /^DP_flow_key\s*:\s(\d+)\s*DP_prefix\s:\s(\d+)\s*$/ )
        {
            $showNat{'DP_flow_key'} = int($1);
            $showNat{'DP_prefix'}   = int($2);
        }
        elsif( /^VLAN_flow_key\s*:\s(\d+)\s*$/ )
        {
            $showNat{'VLAN_flow_key'} = int($1);
        }
        elsif( /^Protocol_flow_key\s*:\s(\d+)\s*$/ )
        {
            $showNat{'Protocol_flow_key'} = int($1);
        }
        elsif( /^Ingress_flow_key\s*:\s(\d+)\s*$/ )
        {
            $showNat{'Ingress_flow_key'} = int($1);
        }
        elsif( /^Ingress\sSlot\s*:\s(\d+)\s*$/ )
        {
            $showNat{'Ingress_Slot'} = int($1);
        }
        elsif( /^Ingress\sPort\s*:\s(\d+)\s*$/ )
        {
            $showNat{'Ingress_Port'} = int($1);
        }
        elsif( /^Interface\sID\s*:\s(\d+)\s*$/ )
        {
            $showNat{'Interface_ID'} = int($1);
        }
        elsif( /^NAT\sIP\sFlow\sType\s*:/ )
        {
            (my $trash, $showNat{'NAT_IP_flow_type'}) = split(/:\s/)
        }
        elsif( /^XSA_data_entry\s*:/ )
        {
            (my $trash, $showNat{'XSA'}) = split(/:\s/)
        }
        elsif( /^XDA_data_entry\s*:/ )
        {
            (my $trash, $showNat{'XDA'}) = split(/:\s/)
        }
        elsif( /^XSP_data_entry\s*:\s(\d+)\s*$/ )
        {
            $showNat{'XSP'} = int($1);
        }
        elsif( /^XDP_data_entry\s*:\s(\d+)\s*$/ )
        {
            $showNat{'XDP'} = int($1);
        }
        elsif( /^Egress_data_entry\s*:\s(\d+)\s*$/ )
        {
            $showNat{'Egress_data_entry'} = int($1);
        }
        elsif( /^Egress\sSlot\s*:\s(\d+)\s*$/ )
        {
            $showNat{'Egress_Slot'} = int($1);
        }
        elsif( /^Egress\sPort\s*:\s(\d+)\s*$/ )
        {
            $showNat{'Egress_Port'} = int($1);
        }
        elsif( /^flow_action\s*:\s0[Xx](\d+)\s*/ )
        {
            (my $trash, $showNat{'flow_action_labels'}) = 
                split(/^flow_action\s*:\s0[Xx][0-9a-fA-F]+\s*/, $_ );
            
            $showNat{'flow_action'} = "0x$1";
        }
        elsif( /^optional_data\s*:\s(\d+)\s*$/ )
        {
            $showNat{'optional_data'} = int($1);
        }
        elsif( /^FPGA_handle\s*:\s0[Xx]([0-9a-fA-F]+)\s*$/ )
        {
            $showNat{'FPGA_handle'} = "0x$1";
        }
        elsif( /^assoc_FPGA_handle\s*:\s0[Xx]([0-9a-fA-F]+)\s*$/ )
        {
            $showNat{'assoc_FPGA_handle'} = "0x$1";
        }
        elsif( /^VLAN_data_entry\s*:\s(\d+)\s*$/ )
        {
            $showNat{'VLAN_data_entry'} = int($1);
        }        
        elsif( /^host_table_index\s*:\s(\d+)\s*$/ )
        {
            $showNat{'host_table_index'} = int($1);
        }
        elsif( /^Switch\sID\s*:\s0[Xx]([0-9a-fA-F]+)\s*$/ )
        {
            $showNat{'Switch_ID'} = $1;
        }
        elsif( /^average-rate\s*:\s(\d+)\s*$/ )
        {
            $showNat{'average_rate'} = int($1);
        }
        elsif( /^weight\s*:\s0[Xx]([0-9a-fA-F]+)\s*$/ )
        {
            $showNat{'weight'} = $1;
        }
        elsif( /^init_flow_guard\s*:\s(\d+)\s*$/ )
        {
            $showNat{'init_flow_guard'} = int($1);
        }
        elsif( /^inact_flow_guard\s*:\s(\d+)\s*$/ )
        {
            $showNat{'inact_flow_guard'} = int($1);
        }
        elsif( /^max_flow_guard\s*:\s(\d+)\s*$/ )
        {
            $showNat{'max_flow_guard'} = int($1);
        }
        elsif( /^payload_type_2833\s:\s(\d+)\s*$/ )
        {
            $showNat{'payload_type_2833'} = int($1);
        }
        elsif( /^index_2833\s*:\s(\d+)\s*$/ )
        {
            $showNat{'index_2833'} = int($1);
        }
        elsif( /^pt_2833_egress\s*:\s(\d+)\s*$/ )
        {
            $showNat{'pt_2833_egress'} = int($1);
        }
        elsif( /^qos_vq_enabled\s*:\s(\d+)\s*$/ )
        {
            $showNat{'qos_vq_enabled'} = int($1);
        }
        elsif( /^codec_type\s*:\s(\d+)\s*$/ )
        {
            $showNat{'codec_type'} = int($1);
        }
        elsif( /^HMU_handle\s*:\s(\d+)\s*$/ )
        {
            $showNat{'HMU_handle'} = int($1);
        }
        elsif( /^SRTP\sCrypto\sIn\s*:/ )
        {
            (my $trash, $showNat{'SRTP_Crypto_In'}) = 
                split(/^SRTP\sCrypto\sIn\s*:/, $_);
        }
        elsif( /^SRTP\sCrypto\sOut\s*:/ )
        {
            (my $trash, $showNat{'SRTP_Crypto_Out'}) = 
                split(/^SRTP\sCrypto\sOut\s*:/, $_);
        }
        #BEGIN USBC/6300 new show nat by-index version matching.
        elsif(/^KEY:\s*src\sinfo\s*:\s/){
            $_ =~ s/\s:\s/@/g; 
            $_ =~ s/\s//g;
            (my $trash, my $temp) = split(/srcinfo@/);
            (my $sa, my $sp) = split (/@/, $temp);
            ($showNat{'SA_flow_key'}, $showNat{'SA_prefix'}) = split(/\//, $sa);
            ($showNat{'SP_flow_key'}, $showNat{'SP_prefix'}) = split(/\//, $sp);
        }
        elsif(/^KEY:\s*dst\sinfo\s*:\s/){
            $_ =~ s/\s:\s/@/g;
            $_ =~ s/\s//g;
            (my $trash, my $temp) = split(/dstinfo@/);
            (my $da, my $dp) = split (/@/, $temp);
            ($showNat{'DA_flow_key'}, $showNat{'DA_prefix'}) = split(/\//, $da);
            ($showNat{'DP_flow_key'}, $showNat{'DP_prefix'}) = split(/\//, $dp);
        }
        else
        {
            #Chopping without checking could remove an actual character.
            if( /\s$/ ){
                chop($_);
            }
            if( ($_ ne "") && ( $_ !~ /^---/ )){
                s/\n//g;
                log_msg("Line not matched: \'$_\'"); 
            }
        }
    }
    log_msg( "Finished parsing show nat by-index results.\n" );

    return %showNat;

}

sub print_nat_hash
{
    #Passing a hash to this function with \%hash, store address in $showNat and
    #dereference with $showNat->{'key'} 
    #Writing this note because this is black magic.

    my $showNat_ref = shift;
    log_msg("Printing keys and values of show nat by-index hash.\n");

    log_msg("total entries      : $showNat_ref->{'total_entries'}");
    log_msg("nat_id             : $showNat_ref->{'nat_id'}");
    log_msg("xsm_addr           : $showNat_ref->{'xsm_addr'}");
    log_msg("max_entries        : $showNat_ref->{'max_entries'}");
    log_msg("flow_type          : $showNat_ref->{'flow_type'}");
    log_msg("SA_flow_key        : $showNat_ref->{'SA_flow_key'}");
    log_msg("SA_prefix          : $showNat_ref->{'SA_prefix'}");
    log_msg("DA_flow_key        : $showNat_ref->{'DA_flow_key'}");
    log_msg("DA_prefix          : $showNat_ref->{'DA_prefix'}");
    log_msg("SP_flow_key        : $showNat_ref->{'SP_flow_key'}");
    log_msg("SP_prefix          : $showNat_ref->{'SP_prefix'}");
    log_msg("DP_flow_key        : $showNat_ref->{'DP_flow_key'}");
    log_msg("DP_prefix          : $showNat_ref->{'DP_prefix'}");
    log_msg("VLAN_flow_key      : $showNat_ref->{'VLAN_flow_key'}");
    log_msg("Protocol_flow_key  : $showNat_ref->{'Protocol_flow_key'}");
    log_msg("Ingress_flow_key   : $showNat_ref->{'Ingress_flow_key'}");
    log_msg("Ingress_Slot       : $showNat_ref->{'Ingress_Slot'}");
    log_msg("Ingress_Port       : $showNat_ref->{'Ingress_Port'}");
    log_msg("Interface_ID       : $showNat_ref->{'Interface_ID'}");
    log_msg("NAT_IP_flow_type   : $showNat_ref->{'NAT_IP_flow_type'}");
    log_msg("XSA                : $showNat_ref->{'XSA'}");
    log_msg("XDA                : $showNat_ref->{'XDA'}");
    log_msg("XSP                : $showNat_ref->{'XSP'}");
    log_msg("XDP                : $showNat_ref->{'XDP'}");
    log_msg("Egress_data_entry  : $showNat_ref->{'Egress_data_entry'}");
    log_msg("Egress_Slot        : $showNat_ref->{'Egress_Slot'}");
    log_msg("Egress_Port        : $showNat_ref->{'Egress_Port'}");
    log_msg("flow_action        : $showNat_ref->{'flow_action'}");
    log_msg("flow_action_labels : $showNat_ref->{'flow_action_labels'}");
    log_msg("optional_data      : $showNat_ref->{'optional_data'}");
    log_msg("FPGA_handle        : $showNat_ref->{'FPGA_handle'}");
    log_msg("assoc_FPGA_handle  : $showNat_ref->{'assoc_FPGA_handle'}");
    log_msg("VLAN_data_entry    : $showNat_ref->{'VLAN_data_entry'}");
    log_msg("host_table_index   : $showNat_ref->{'host_table_index'}");
    log_msg("Switch_ID          : $showNat_ref->{'Switch_ID'}");
    log_msg("average_rate       : $showNat_ref->{'average_rate'}");
    log_msg("weight             : $showNat_ref->{'weight'}");
    log_msg("init_flow_guard    : $showNat_ref->{'init_flow_guard'}");
    log_msg("inact_flow_guard   : $showNat_ref->{'inact_flow_guard'}");
    log_msg("max_flow_guard     : $showNat_ref->{'max_flow_guard'}");
    log_msg("payload_type_2833  : $showNat_ref->{'payload_type_2833'}");
    log_msg("index_2833         : $showNat_ref->{'index_2833'}");
    log_msg("pt_2833_egress     : $showNat_ref->{'pt_2833_egress'}");
    log_msg("qos_vq_enabled     : $showNat_ref->{'qos_vq_enabled'}");
    log_msg("codec_type         : $showNat_ref->{'codec_type'}");
    log_msg("HMU_handle         : $showNat_ref->{'HMU_handle'}");
    log_msg("SRTP_Crypto_In     : $showNat_ref->{'SRTP_Crypto_In'}");
    log_msg("SRTP_Crypto_Out    : $showNat_ref->{'SRTP_Crypto_Out'}");


    log_msg("\nDone printing showNat hash.\n");

}
    
sub resolve_L2
{
    my $argument = "";
    my $count    = 5;
    my $rda      = "";
    my $rif      = "";
    my $rsa      = "";

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?rsa$/i)
            {
                $rsa = $argument;
            }
            elsif(/^-?rda$/i)
            {
                $rda = $argument;
            }
            elsif(/^-?rif$/i)
            {
                $rif = $argument;
            }
            elsif(/^-?count/i)
            {
                $count = $argument;
            }
        }
    }
    if(is_v6($rda)){
        log_msg("Resolving Neighbor Solicitation.");
        
        log_msg("Sending Command: ndisc6 $rda $rif $rsa -r $count");
        my @ndiscResult = `ndisc6 $rda $rif $rsa -r $count`;
        
        foreach(@ndiscResult){
            chomp($_);
            print("$_\n");
            
            if( /^No\sresponse.\s*/ ){
                log_msg("Error: Unable to resolve Neighbor Soliciation.");
                return 1;
            }
        }
    }
    else{
        log_msg("Resolving ARP.");
        log_msg("Sending Command: arping -c $count -I $rif $rda");
        my @arpResult = `sudo arping -c $count -I $rif $rda`;
                
        foreach(@arpResult){
            chomp($_);
            print("$_\n");
            
            if( /Received\s0\sresponse\(s\)/ ){
                log_msg("Error: Unable to resolve ARP.");
                return 1;
            }
        }
    }

    return 0;
}

1;
