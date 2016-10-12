# Written by Scott McCulley

package Acme::Flow;

use strict;
use Net::Telnet;
use Acme::embtestlib;
use Switch;

############################
## the object constructor ##
############################
sub new
{
    my $class = shift;
    my $self = {};
    $self->{type}    = "SD3";
    $self->{name}    = undef;
    $self->{session} = undef;
    $self->{ppxFlowID} = "";

    # Checks @_ for well-defined parameters and their corresponding arguments
    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        # Removes 2 items from the front of @_ using the first as an identifier and the second as its argument
        while( ( $_, my $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?session$/i )
            {
                $self->{session} = $argument;
            }
            elsif( /^-?type$/i )
            {
                $self->{type} = $argument;
            }
            elsif( /^-?name$/i )
            {
                $self->{name} = $argument;
            }
        }
    }
    else
    {
        if(@_ == 0)
        {
            sprintf "Please provide session and name(of the SBC)\n";
        }
        else
        {
            sprintf "Odd number of parameters detected, please check your syntax\n";
        }
        undef $self;
        return $self;
    }

    # Check to make sure that a provided telnet session has been provided
    if (!defined($self->{session}))
    {
        log_msg("Can't connect to SD HOST, please provide the session");
        undef $self;
        return $self;
    }

    # Associates $self with the class Acme::Flow. Now when trying to invoke a method on the $self object
    # perl knows to look in the package Acme::Flow for its functions.
    bless($self, $class);
    return $self;
}

sub getSession
{
    my $self = shift;
    return $self->{session};
}

sub setSession
{
    my $self = shift;
    $self->{session} = shift;
}

sub getName
{
    my $self = shift;
    return $self->{name};
}

sub setName
{
    my $self = shift;
    $self->{name} = shift;
}

sub getPpxFlowID
{
    my $self = shift;
    return $self->{ppxFlowID};
}

sub setPpxFlowID
{
    my $self = shift;
    $self->{ppxFlowID} = shift;
}

sub getFgIndex
{
    my $self = shift;
    my $argument = "";
    my $ppxFlowID = "";
    my @results = ();
    my $prematch = "";
    my $match = "";

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
              $ppxFlowID = $argument;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 0;
    }

    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 0;
    }

    @results = $self->{session}->cmd( String => "PPX_show_by_id $ppxFlowID",
                                      Timeout => 10,
                                      Prompt => "/->|acli-shell:/" );
    foreach(@results)
    {
        if($_ =~ /FG-index:\s*(\d+)/)
        {
            return $1;
        }
    }

    return 0;
}

sub ppxFlowCreate
{
    #initialise to empty for default (media) case
    #use test_ppx_flow_create()
    my $acl  = ""; 
    my $self = shift;
    my $acl  = shift;
    my @res;

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    if($self->{ppxFlowID} ne "")
    {
        log_msg("About to overwrite exiting ppxFlowID($self->{ppxFlowID})", "WARNING");
    }

    if($acl eq "")
    {
        #Create PPX flow to be used for adding PPM's
        @res = $self->{session}->cmd( String => "test_ppx_flow_create",
                                         Timeout => 10,
                                         Prompt => "/->|acli-shell:/" );
    }
    else {
        switch($acl)
        {
            case "denied"           { @res = $self->{session}->cmd(  String  => "test_ppx_flow_create_by_access 0",
                                                                     Timeout => 10,
                                                                     Prompt  => "/->|acli-shell:/" ); }
            case "media"            { @res = $self->{session}->cmd(  String => "test_ppx_flow_create_by_access 1",
                                                                     Timeout => 10,
                                                                     Prompt => "/->|acli-shell:/" ); }
            case "trusted"          { @res = $self->{session}->cmd(  String => "test_ppx_flow_create_by_access 2",
                                                                     Timeout => 10,
                                                                     Prompt => "/->|acli-shell:/" ); }
            case "untrusted"        { @res = $self->{session}->cmd(  String => "test_ppx_flow_create_by_access 3",
                                                                     Timeout => 10,
                                                                     Prompt => "/->|acli-shell:/" ); }
            case "intfc table"      { @res = $self->{session}->cmd(  String => "test_ppx_flow_create_by_access 4",
                                                                     Timeout => 10,
                                                                     Prompt => "/->|acli-shell:/" ); }
            case "dynamic trusted"  { @res = $self->{session}->cmd(  String => "test_ppx_flow_create_by_access 5",
                                                                     Timeout => 10,
                                                                     Prompt => "/->|acli-shell:/" ); }
            else                    { return 1; }
        }
    }

    if( ( $self->{ppxFlowID} = parseReturnValue( @res ) ) == 0 )
    {
        return 0;
    }

    return $self->{ppxFlowID};
}

sub ppxFlowAddFeatureNat
{
    my $self = shift;
    my $options = "";
    my $intfOptions = "";
    my $argument = "";
    my $vaArgs = "";
    my $intfVaArgs = "";
    my $ppxFlowID = "";
    my $prematch = "";
    my $match = "";
    my $count = 0;
    my @argList = ();

    my $do_collapse = 0;
    my $do_srs      = 0;
    my $access_type = "";

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
              $ppxFlowID = $argument;
              next;
            }

            if(/^-?sa$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "sa";
                $vaArgs = $vaArgs . ", " . surroundWithQuotes($argument);
            }
            elsif(/^-?sa_prefix$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "sa_prefix";
                $vaArgs = $vaArgs . ", " . $argument; 
            }
            elsif(/^-?da$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "da";
                $vaArgs = $vaArgs . ", " . surroundWithQuotes($argument);
            }
            elsif(/^-?da_prefix$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "da_prefix";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?sp$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "sp";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?sp_prefix$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "sp_prefix";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?dp$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "dp";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?dp_prefix$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "dp_prefix";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?xsa$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "xsa";
                $vaArgs = $vaArgs . ", " . surroundWithQuotes($argument);
            }
            elsif(/^-?xda$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "xda";
                $vaArgs = $vaArgs . ", " . surroundWithQuotes($argument);
            }
            elsif(/^-?xsp$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "xsp";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?xdp$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "xdp";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?igr_slot$/i)
            {
                if($intfOptions ne "")
                {
                    $intfOptions = $intfOptions . ", ";
                }

                $intfOptions = $intfOptions . "igr_slot";
                $intfVaArgs = $intfVaArgs . ", " . $argument;
            }
            elsif(/^-?igr_port$/i)
            {
                if($intfOptions ne "")
                {
                    $intfOptions = $intfOptions . ", ";
                }

                $intfOptions = $intfOptions . "igr_port";
                $intfVaArgs = $intfVaArgs . ", " . $argument;
            }
            elsif(/^-?igr_vlan$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "igr_vlan";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?egr_slot$/i)
            {
                if($intfOptions ne "")
                {
                    $intfOptions = $intfOptions . ", ";
                }

                $intfOptions = $intfOptions . "egr_slot";
                $intfVaArgs = $intfVaArgs . ", " . $argument;
            }
            elsif(/^-?egr_port$/i)
            {
                if($intfOptions ne "")
                {
                    $intfOptions = $intfOptions . ", ";
                }

                $intfOptions = $intfOptions . "egr_port";
                $intfVaArgs = $intfVaArgs . ", " . $argument;
            }
            elsif(/^-?egr_vlan$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "egr_vlan";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?init_fg$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "init_fg";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?inact_fg$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "inact_fg";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?max_fg$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "max_fg";
                $vaArgs = $vaArgs . ", " . $argument;
            }
	        elsif(/^-?flags$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }

                $count++;

                $options = $options . "flags";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?collapsed$/i)
            {
                $do_collapse = $argument;
                push(@argList, ", \"collapsed\", $do_collapse" );
            }
            elsif(/^-?srs$/i)
            {
                $do_srs = $argument;
                push(@argList, ", \"srs\", $do_srs");
            }
            elsif(/^-?access_type$/i)
            {
                $access_type = $argument;
                push(@argList, ", \"access_type\", \"$access_type\"");
            }
            elsif(/^-?slow_port$/i)
            {
                if($options ne "")
                {
                    $options = $options . ", ";
                }
                
                $count++;
                
                $options = $options . "slow_port";
                $vaArgs = $vaArgs . ", " . surroundWithQuotes($argument);
            }
            else
            {
                sprintf "Option not currently available for this feature\n";
                next;
            }

            if($count >= 4)
            {
                push(@argList, ", " . surroundWithQuotes($options) . $vaArgs);
                $options = "";
                $vaArgs = "";
                $count = 0;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }

    if($options ne "" && $vaArgs ne "")
    {
        push(@argList, ", "  . surroundWithQuotes($options) . $vaArgs);
        $options = "";
        $vaArgs = "";
        $count = 0;
    }

    if($intfOptions ne "" && $intfVaArgs ne "")
    {
        push(@argList, ", "  . surroundWithQuotes($intfOptions) . $intfVaArgs);
        $intfOptions = "";
        $intfVaArgs = "";
    }

    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    if(@argList)
    {
        foreach(@argList)
        {
            $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"NAT\"" . $_);
            ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
        }
    }
    else
    {
        $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"NAT\", \"\"");
        ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
    }

    return 0;
}

sub ppxFlowAddFeatureXtone
{
    my $self = shift;
    my $options = "";
    my $argument = "";
    my $vaArgs = "";
    my $ppxFlowID = "";
    my $prematch = "";
    my $match = "";
    my $count = 0;
    my @argList = ();

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
              $ppxFlowID = $argument;
              next;
            }

            if($count)
            {
                $options = $options . ", ";
            }

            if(/^-?pt$/i)
            {
                $options = $options . "pt";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?pt_codec$/i)
            {
                $options = $options . "pt_codec";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?freq$/i)
            {
                $options = $options . "freq";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?ptime$/i)
            {
                $options = $options . "ptime";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            else
            {
                sprintf "Option not currently available for this feature\n";
            }

            $count++;

            if($count >= 4)
            {
                push(@argList, ", " . surroundWithQuotes($options) . $vaArgs);
                $options = "";
                $vaArgs = "";
                $count = 0;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }

    if($options ne "" && $vaArgs ne "")
    {
        push(@argList, ", "  . surroundWithQuotes($options) . $vaArgs);
        $options = "";
        $vaArgs = "";
        $count = 0;
    }

    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    if(@argList)
    {
        foreach(@argList)
        {
            $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"XTONE\"" . $_);
            ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
        }
    }
    else
    {
        $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"XTONE\", \"\"");
        ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
    }

    return 0;
}

sub ppxFlowAddFeatureTos
{
    my $self = shift;
    my $options = "";
    my $argument = "";
    my $vaArgs = "";
    my $ppxFlowID = "";
    my $prematch = "";
    my $match = "";
    my $count = 0;
    my @argList = ();

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
              $ppxFlowID = $argument;
              next;
            }

            if($count)
            {
                $options = $options . ", ";
            }

            if(/^-?tos$/i)
            {
                $options = $options . "tos";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            else
            {
                sprintf "Option not currently available for this feature\n";
            }

            $count++;

            if($count >= 4)
            {
                push(@argList, ", " . surroundWithQuotes($options) . $vaArgs);
                $options = "";
                $vaArgs = "";
                $count = 0;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }

    if($options ne "" && $vaArgs ne "")
    {
        push(@argList, ", "  . surroundWithQuotes($options) . $vaArgs);
        $options = "";
        $vaArgs = "";
        $count = 0;
    }

    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    if(@argList)
    {
        foreach(@argList)
        {
            $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"TOS\"" . $_);
            ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
        }
    }
    else
    {
        $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"TOS\"");
        ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
    }

    return 0;
}

sub ppxFlowAddFeatureLi
{
    my $self = shift;
    my $options = "";
    my $argument = "";
    my $vaArgs = "";
    my $ppxFlowID = "";
    my $prematch = "";
    my $match = "";
    my $count = 0;
    my @argList = ();

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
              $ppxFlowID = $argument;
              next;
            }

            if($count)
            {
                $options = $options . ", ";
            }

            if(/^-?li_index$/i)
            {
                $options = $options . "li_index";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            else
            {
                sprintf "Option not currently available for this feature\n";
            }

            $count++;

            if($count >= 4)
            {
                push(@argList, ", " . surroundWithQuotes($options) . $vaArgs);
                $options = "";
                $vaArgs = "";
                $count = 0;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }

    if($options ne "" && $vaArgs ne "")
    {
        push(@argList, ", "  . surroundWithQuotes($options) . $vaArgs);
        $options = "";
        $vaArgs = "";
        $count = 0;
    }

    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    if(@argList)
    {
        foreach(@argList)
        {
            $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"LI\"" . $_);
            ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
        }
    }
    else
    {
        $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"LI\"");
        ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
    }

    return 0;
}

sub ppxFlowAddFeatureSrtpD
{
    my $self = shift;
    my $options = "";
    my $argument = "";
    my $vaArgs = "";
    my $ppxFlowID = "";
    my $prematch = "";
    my $match = "";
    my $count = 0;
    my @argList = ();

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
              $ppxFlowID = $argument;
              next;
            }

            if($count)
            {
                $options = $options . ", ";
            }

            if(/^-?key$/i)
            {
                $options = $options . "key";
                $vaArgs = $vaArgs . ", " . surroundWithQuotes($argument);
            }
            elsif(/^-?key_len$/i)
            {
                $options = $options . "key_len";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            else
            {
                sprintf "Option not currently available for this feature\n";
            }

            $count++;

            if($count >= 4)
            {
                push(@argList, ", " . surroundWithQuotes($options) . $vaArgs);
                $options = "";
                $vaArgs = "";
                $count = 0;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }

    if($options ne "" && $vaArgs ne "")
    {
        push(@argList, ", "  . surroundWithQuotes($options) . $vaArgs);
        $options = "";
        $vaArgs = "";
        $count = 0;
    }

    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    if(@argList)
    {
        foreach(@argList)
        {
            $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"SRTPD\"" . $_);
            ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
        }
    }
    else
    {
        $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"SRTPD\", \"\"");
        ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
    }

    return 0;
}

sub ppxFlowAddFeatureSrtpE
{
    my $self = shift;
    my $options = "";
    my $argument = "";
    my $vaArgs = "";
    my $ppxFlowID = "";
    my $prematch = "";
    my $match = "";
    my $count = 0;
    my @argList = ();

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
              $ppxFlowID = $argument;
              next;
            }

            if($count)
            {
                $options = $options . ", ";
            }

            if(/^-?key$/i)
            {
                $options = $options . "key";
                $vaArgs = $vaArgs . ", " . surroundWithQuotes($argument);
            }
            elsif(/^-?key_len$/i)
            {
                $options = $options . "key_len";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            else
            {
                sprintf "Option not currently available for this feature\n";
            }

            $count++;

            if($count >= 4)
            {
                push(@argList, ", " . surroundWithQuotes($options) . $vaArgs);
                $options = "";
                $vaArgs = "";
                $count = 0;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }

    if($options ne "" && $vaArgs ne "")
    {
        push(@argList, ", "  . surroundWithQuotes($options) . $vaArgs);
        $options = "";
        $vaArgs = "";
        $count = 0;
    }

    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    if(@argList)
    {
        foreach(@argList)
        {
            $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"SRTPE\"" . $_);
            ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
        }
    }
    else
    {
        $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"SRTPE\", \"\"");
        ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
    }
    return 0;
}

sub ppxFlowAddFeatureQos
{
    my $self = shift;
    my $options = "";
    my $argument = "";
    my $vaArgs = "";
    my $ppxFlowID = "";
    my $prematch = "";
    my $match = "";
    my $count = 0;
    my @argList = ();

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
              $ppxFlowID = $argument;
              next;
            }

            if($count)
            {
                $options = $options . ", ";
            }

            if(/^-?collapsed$/i)
            {
                $options = $options . "collapsed";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?flow_type$/i)
            {
                $options = $options . "flow_type";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?codec_type$/i)
            {
                $options = $options . "codec_type";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?frequency$/i)
            {
                $options = $options . "frequency";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?ptime$/i)
            {
                $options = $options . "ptime";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?handle$/i)
            {
                $options = $options . "handle";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?fwd_flow_id$/i)
            {
                $options = $options . "fwd_flow_id";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?rev_flow_id$/i)
            {
                $options = $options . "rev_flow_id";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            else
            {
                sprintf "Option not currently available for this feature\n";
            }

            $count++;

            if($count >= 4)
            {
                push(@argList, ", " . surroundWithQuotes($options) . $vaArgs);
                $options = "";
                $vaArgs = "";
                $count = 0;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }

    if($options ne "" && $vaArgs ne "")
    {
        push(@argList, ", "  . surroundWithQuotes($options) . $vaArgs);
        $options = "";
        $vaArgs = "";
        $count = 0;
    }

    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    if(@argList)
    {
        foreach(@argList)
        {
            $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"QOS\"" . $_);
            ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
        }
    }
    else
    {
        $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"QOS\", \"\"");
        ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
    }

    return 0;
}

sub ppxFlowAddFeatureHmu
{
    my $self = shift;
    my $options = "";
    my $argument = "";
    my $vaArgs = "";
    my $ppxFlowID = "";
    my $prematch = "";
    my $match = "";
    my $count = 0;
    my @argList =();

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
              $ppxFlowID = $argument;
	      next;
            }

	    if($count)
	    {
		$options = $options . ", ";
	    }

	    if(/^-?hmu_handle$/i)
	    {
		$options = $options . "hmu_handle";
		$vaArgs  = $vaArgs . ", " . $argument;
	    }
	    
	    elsif(/^-?hmu_cleanup$/i)
	    {
		$options = $options . "hmu_cleanup";
		$vaArgs  = $vaArgs . ", " . $argument;
	    }
	    
            else
            {
		
                sprintf "Option not currently available for this feature\n";
            }

	    $count++;
	    
	    if($count >= 4)
            {
                push(@argList, ", " . surroundWithQuotes($options) . $vaArgs);
                $options = "";
                $vaArgs = "";
                $count = 0;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }

    if($options ne "" && $vaArgs ne "")
    {
	push(@argList, ", "  . surroundWithQuotes($options) . $vaArgs);
        $options = "";
        $vaArgs = "";
        $count = 0;
    }
    
    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    if(@argList)
    {
	foreach(@argList)
	{
#	    $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"HMU\", \"\"" . $_);
	    $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"HMU\"" . $_);
	    ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
	}
    }
    else
    {
	$self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"HMU\", \"\"");
#	$self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"HMU\"");
	( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
    }
    
    return 0;
}

sub ppxFlowAddFeatureLatch
{
    my $self = shift;
    my $argument = "";
    my $vaArgs = "";
    my $ppxFlowID = "";
    my $prematch = "";
    my $match = "";
    my $do_latch = 0;

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
                $ppxFlowID = $argument;
            }
            elsif(/^-?do_latch$/i)
            {
                $do_latch = $argument;
            }
            else
            {
                sprintf "Option not currently available for this feature\n";
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }

    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"LATCH\", $do_latch");
    ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );

    return 0;

}

sub ppxFlowAddFeatureCrs
{
    my $self = shift;
    my $options = "";
    my $argument = "";
    my $vaArgs = "";
    my $ppxFlowID = "";
    my $prematch = "";
    my $match = "";
    my $count = 0;
    my @argList = ();

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
              $ppxFlowID = $argument;
              next;
            }

            if($count)
            {
                $options = $options . ", ";
            }

            if(/^-?crs_id$/i)
            {
                $options = $options . "crs_id";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?crs_dir$/i)
            {
                $options = $options . "crs_dir";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            else
            {
                sprintf "Option not currently available for this feature\n";
            }

            $count++;

            if($count >= 4)
            {
                push(@argList, ", " . surroundWithQuotes($options) . $vaArgs);
                $options = "";
                $vaArgs = "";
                $count = 0;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }

    if($options ne "" && $vaArgs ne "")
    {
        push(@argList, ", "  . surroundWithQuotes($options) . $vaArgs);
        $options = "";
        $vaArgs = "";
        $count = 0;
    }

    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    if(@argList)
    {
        foreach(@argList)
        {
            $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"CRS\"" . $_);
            ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
        }
    }
    else
    {
        $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"CRS\"");
        ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
    }

    return 0;
}
sub ppxFlowAddFeatureSrs
{
    my $self = shift;
    my $options = "";
    my $argument = "";
    my $vaArgs = "";
    my $ppxFlowID = "";
    my $prematch = "";
    my $match = "";
    my $count = 0;
    my @argList = ();

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
              $ppxFlowID = $argument;
              next;
            }

            if($count)
            {
                $options = $options . ", ";
            }

            if(/^-?srs_index$/i)
            {
                $options = $options . "index";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?srs_next$/i)
            {
                $options = $options . "next";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            else
            {
                sprintf "Option not currently available for this feature\n";
            }

            $count++;

            if($count >= 4)
            {
                push(@argList, ", " . surroundWithQuotes($options) . $vaArgs);
                $options = "";
                $vaArgs = "";
                $count = 0;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }

    if($options ne "" && $vaArgs ne "")
    {
        push(@argList, ", "  . surroundWithQuotes($options) . $vaArgs);
        $options = "";
        $vaArgs = "";
        $count = 0;
    }

    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    if(@argList)
    {
        foreach(@argList)
        {
            $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"SRS\"" . $_);
            ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
        }
    }
    else
    {
        $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"SRS\"");
        ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
    }

    return 0;
}
sub ppxFlowAddFeature2833
{
    my $self = shift;
    my $options = "";
    my $argument = "";
    my $vaArgs = "";
    my $ppxFlowID = "";
    my $prematch = "";
    my $match = "";
    my $count = 0;
    my @argList = ();

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
              $ppxFlowID = $argument;
              next;
            }

            if($count)
            {
                $options = $options . ", ";
            }

            if(/^-?detect$/i)
            {
                $options = $options . "detect";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?generate$/i)
            {
                $options = $options . "generate";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?dual$/i)
            {
                $options = $options . "dual";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?pt$/i)
            {
                $options = $options . "pt";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?pt_egress$/i)
            {
                $options = $options . "pt_egress";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            elsif(/^-?index$/i)
            {
                $options = $options . "index";
                $vaArgs = $vaArgs . ", " . $argument;
            }
            else
            {
                sprintf "Option not currently available for this feature\n";
            }

            $count++;

            if($count >= 4)
            {
                push(@argList, ", " . surroundWithQuotes($options) . $vaArgs);
                $options = "";
                $vaArgs = "";
                $count = 0;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }

    if($options ne "" && $vaArgs ne "")
    {
        push(@argList, ", "  . surroundWithQuotes($options) . $vaArgs);
        $options = "";
        $vaArgs = "";
        $count = 0;
    }

    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    if(@argList)
    {
        foreach(@argList)
        {
            $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"2833\"" . $_);
            ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
        }
    }
    else
    {
        $self->{session}->print("test_ppx_flow_add_feature $ppxFlowID, \"2833\"");
        ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
    }

    return 0;
}

sub ppxFlowDeleteFeature
{
    my $self = shift;
    my $ppxFlowID = "";
    my $prematch = "";
    my $match = "";
    my $feature = "";

    if(/^-?NAT$/i)
    {
        $feature = "NAT";
    }
    elsif(/^-?XTONE$/i)
    {
        $feature = "XTONE";
    }
    elsif(/^-?SRTPE$/i)
    {
        $feature = "SRTPE";
    }
    elsif(/^-?SRTPD$/i)
    {
        $feature = "SRTPD";
    }
    elsif(/^-?HMU$/i)
    {
        $feature = "HMU";
    }
    elsif(/^-?IPT$/i)
    {
        $feature = "IPT";
    }
    elsif(/^-?LI$/i)
    {
        $feature = "LI";
    }
    elsif(/^-?QOS$/i)
    {
        $feature = "QOS";
    }
    elsif(/^-?2833$/i)
    {
        $feature = "2833";
    }
    elsif(/^-?TOS$/i)
    {
        $feature = "TOS";
    }
    elsif(/^-?CRS$/i)
    {
        $feature = "CRS";
    }
    elsif(/^-?SRS$/i)
    {
        $feature = "SRS";
    }
    else
    {
        sprintf "Option not currently available for this feature\n";
        return 1;
    }
    
    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }
    
    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    $self->{session}->print("test_ppx_flow_delete_feature $ppxFlowID, \"$feature\"");
    ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
    
    return 0;
}


sub ppxFlowApply
{
    my $self = shift;
    my $argument = "";
    my $ppxFlowID = "";
    my @results = ();
    my $prematch = "";
    my $match = "";
    my $noDestroy = 0;

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
              $ppxFlowID = $argument;
            }
            if(/^-?no_destroy$/i)
            {
                $noDestroy = 1;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }
    
    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    @results = $self->{session}->cmd( String => "PPX_ppm_apply $ppxFlowID",
                                      Timeout => 10,
                                      Prompt => "/->|acli-shell:/" );


    if( parseReturnValue( @results ) != 0 )
    {
        if(!$noDestroy)
        {
            #return of value != 0 is FAILURE from either type of the above commands
            $self->{session}->print( "test_ppx_flow_destroy $ppxFlowID" );
            ( $prematch, $match ) = $self->{session}->waitfor( Match => "/->|acli-shell:/" );
        }

        # Dump log when flow apply failed
        if(dump_log(Session => $self->{session}, Name => $self->{name}))
        {
            log_msg("ERROR: Could not dump log.");
        }

        return 1;
    }

    return 0;
}

sub ppxFlowDestroy
{
    my $self = shift;
    my $argument = "";
    my $ppxFlowID = "";
    my @results = ();
    my $prematch = "";
    my $match = "";

    if((@_ > 0) && (( @_ % 2 ) == 0))
    {
        while(($_, $argument) = splice( @_, 0, 2 ))
        {
            if(/^-?ppxFlowID$/i)
            {
                $ppxFlowID = $argument;
            }
        }
    }
    elsif(( @_ % 2 ) != 0)
    {
        log_msg("Odd number of parameters detected, please check your syntax", "ERROR");
        return 1;
    }

    if($ppxFlowID eq "")
    {
        $ppxFlowID = $self->{ppxFlowID};
    }

    if(sdGoToShellPrompt(Session => $self->{session}, Name => $self->{name}))
    {
        log_msg("ERROR: Could not reach '->' prompt.");
        return 1;
    }

    @results = $self->{session}->cmd( String => "test_ppx_flow_destroy $ppxFlowID",
                                      Timeout => 10,
                                      Prompt => "/->|acli-shell:/" );
    if( parseReturnValue( @results ) != 0 )
    {
        #Dump log when flow destroy failed
        if(dump_log(Session => $self->{session}, Name => $self->{name}))
        {
            log_msg("ERROR: Could not dump log.");
        }

        #return of value != 0 is FAILURE
        return undef;
    }

    return @results;
}




1;
