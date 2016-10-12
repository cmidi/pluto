#!/usr/bin/perl

package Acme::fgtestlib;

use Acme::embtestlib;
use Acme::ip;
use Exporter;
use Net::Telnet;
use Switch;
use POSIX;

our @ISA = qw( Exporter );

# these can be exported.
our @EXPORT_OK = qw( sd_listener_send_rtp_packets PPM_NAT_add_flow PPM_NAT_add_flow2 PPM_NAT_config_flow PPM_NAT_add_flow_loop PPM_NAT_add_flow_loop_by_DA PPM_NAT_verify_flow PPM_NAT_verify_flow_exist_loop PPM_NAT_verify_flow_destroy_loop PPM_NAT_delete_flow PPM_NAT_delete_flow_loop increment_IP_addr increment_IP_addr_v4 increment_IP_addr_v6 get_num_shuffles increment_IP_addr_v4_2 increment_IP_addr_v6_2 increment_IP_addr_2 expand_IP_addr);

# these are exported by default
our @EXPORT = qw( sd_listener_send_rtp_packets PPM_NAT_add_flow PPM_NAT_add_flow2 PPM_NAT_config_flow PPM_NAT_add_flow_loop PPM_NAT_add_flow_loop_by_DA PPM_NAT_verify_flow PPM_NAT_verify_flow_exist_loop PPM_NAT_verify_flow_destroy_loop PPM_NAT_delete_flow PPM_NAT_delete_flow_loop increment_IP_addr increment_IP_addr_v4 increment_IP_addr_v6 get_num_shuffles increment_IP_addr_v4_2 increment_IP_addr_v6_2 increment_IP_addr_2 expand_IP_addr);

sub sd_listener_send_rtp_packets
{
    my %flowParameters = ();
    my %listenerParameters = ();
    my $command = "";
    my @results = ();
    
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?flow$/i )
            {
                %flowParameters = %{$argument};
            }
            elsif( /^-?listener$/i )
            {
                %listenerParameters = %{$argument};
            }
        }
    }
    
    log_msg("In sd_listener_send_rtp_packets using a timeout of 15 seconds");

    #Send rtp packet
    $command = "sd_listener --rsa $flowParameters{'rsa'} " .
                           "--rsp $flowParameters{'rsp'} " .
                           "--rda $flowParameters{'rda'} " .
                           "--rdp $flowParameters{'rdp'} " .
                           "--rttl $flowParameters{'rttl'} " .
                           "--rpc $listenerParameters{'rpcap'} " .
                           "--rif $listenerParameters{'rif'} " .
                        
                           "--lsa $flowParameters{'lsa'} " .
                           "--lsp $flowParameters{'lsp'} " .
                           "--lda $flowParameters{'lda'} " .
                           "--ldp $flowParameters{'ldp'} " .
                           "--lttl $flowParameters{'lttl'} " .
                           "--lpc $listenerParameters{'lpcap'} " .
                           "--lif $listenerParameters{'lif'} " .
                           "--tmo 15";
                        
    log_msg("Executing: $command\n");
    
    my @results = `$command`;
    log_msg("SD_Listener Results:\n@results");
    @results = trimArray( @results );
}

#slow to add many NATs at once
sub PPM_NAT_add_flow
{
    my $telnet = "";
    my %sbcInfo = ();
    my %flowParameters = ();
    my %fgParameters = ();
    my $access_type = "";
    
    #pull in variables
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?telnet$/i )
            {
                $telnet = $argument;
            }
            elsif( /^-?info$/i )
            {
                %sbcInfo = %{$argument};
            }
            elsif( /^-?flow$/i )
            {
                %flowParameters = %{$argument};
            }
            elsif( /^-?timers$/i )
            {
                %fgParameters = %{$argument};
            }
            elsif( /^-?access$/i )
            {
                $access_type = $argument;
            }                      
        }
    }
    
    #go to shell
    $telnet->print( "" );
    ( $prematch, $match ) = $telnet->waitfor( Match => "/->|acli-shell:/",
                                              Timeout => 1,
                                              Errmode => "return" );
    if( $telnet->errmsg ne "" )
    {
        sdGoToShellPrompt(Session => $telnet, Name => $sbcInfo{'sdname'});
    }
    
    #config slot, port, vlan
    $telnet->cmd( String => "test_set_ppm_nat_cfg_intf(".
                            "$flowParameters{'rslot'},".
                            "$flowParameters{'rport'},".
                            "$flowParameters{'rvlan'},".
                            "$flowParameters{'lslot'},".
                            "$flowParameters{'lport'},".
                            "$flowParameters{'lvlan'})",
                  Timeout => (10),
                  Prompt => "/->|acli-shell:/" );
                 
    #config source and dest addrs and ports
    $telnet->cmd( String => "test_set_ppm_nat_cfg(".
                            "\"$flowParameters{'rsa'}\", ".
                            "\"$flowParameters{'rda'}\", ".
                            "$flowParameters{'rsp'}, ".
                            "$flowParameters{'rdp'}, ".
                            "\"$flowParameters{'lsa'}\", ".
                            "\"$flowParameters{'lda'}\", ".
                            "$flowParameters{'lsp'}, ".
                            "$flowParameters{'ldp'})",
                  Timeout => (10),
                  Prompt => "/->|acli-shell:/" );
                  
    #config fg parameters
    $telnet->cmd( String => "test_set_ppm_nat_cfg_fg(".
                            "$fgParameters{'init_timer'}, ".
                            "$fgParameters{'inact_timer'}, ".
                            "$fgParameters{'max_timer'}, ".
                            "$access_type)",
                  Timeout => (10),
                  Prompt => "/->|acli-shell:/" );

    #create flow              
    foreach($telnet->cmd( String => "test_ppx_flow_create_nat()",
                          Timeout => (10),
                          Prompt => "/->|acli-shell:/" ))
    {
        if($_ =~ m/value = (\d+)/i)
        {
            return $1;
        }
    }   
    
}

#must call PPM_NAT_config_flow first
sub PPM_NAT_add_flow2
{
    my $telnet = "";
    my %sbcInfo = ();
    my %flowParameters = ();
    my %fgParameters = ();
    my $access_type = "";
    
    #pull in variables
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?telnet$/i )
            {
                $telnet = $argument;
            }
            elsif( /^-?info$/i )
            {
                %sbcInfo = %{$argument};
            }
            elsif( /^-?flow$/i )
            {
                %flowParameters = %{$argument};
            }
            elsif( /^-?timers$/i )
            {
                %fgParameters = %{$argument};
            }
            elsif( /^-?access$/i )
            {
                $access_type = $argument;
            }                      
        }
    }
    
    #go to shell
    $telnet->print( "" );
    ( $prematch, $match ) = $telnet->waitfor( Match => "/->|acli-shell:/",
                                              Timeout => 1,
                                              Errmode => "return" );
    if( $telnet->errmsg ne "" )
    {
        sdGoToShellPrompt(Session => $telnet, Name => $sbcInfo{'sdname'});
    }

    #create flow              
    foreach($telnet->cmd( String => "test_CAM_add_flow(".
                            "\"$flowParameters{'rsa'}\", ".
                            "\"$flowParameters{'rda'}\", ".
                            "$flowParameters{'rsp'}, ".
                            "$flowParameters{'rdp'}, ".
                            "\"$flowParameters{'lsa'}\", ".
                            "\"$flowParameters{'lda'}\", ".
                            "$flowParameters{'lsp'}, ".
                            "$flowParameters{'ldp'}, ".
                            "$access_type)",
                  Timeout => (10),
                  Prompt => "/->|acli-shell:/" ))
    {
        if($_ =~ m/value = (\d+)/i)
        {
            return $1;
        }
    }   
    
}

sub PPM_NAT_config_flow
{
    my $telnet = "";
    my %sbcInfo = ();
    my %flowParameters = ();
    my %fgParameters = ();
    
    # media = 1
    my $access_type = 1;
    
    #pull in variables
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?telnet$/i )
            {
                $telnet = $argument;
            }
            elsif( /^-?info$/i )
            {
                %sbcInfo = %{$argument};
            }
            elsif( /^-?flow$/i )
            {
                %flowParameters = %{$argument};
            }
            elsif( /^-?timers$/i )
            {
                %fgParameters = %{$argument};
            }
            elsif( /^-?access$/i )
            {
                $access_type = $argument;
            }                      
        }
    }
    
    #go to shell
    $telnet->print( "" );
    ( $prematch, $match ) = $telnet->waitfor( Match => "/->|acli-shell:/",
                                              Timeout => 1,
                                              Errmode => "return" );
    if( $telnet->errmsg ne "" )
    {
        sdGoToShellPrompt(Session => $telnet, Name => $sbcInfo{'sdname'});
    }
    
    $telnet->cmd( String => "test_CAM_config_flow(".
                            "$fgParameters{'init_timer'},".
                            "$fgParameters{'inact_timer'},".
                            "$fgParameters{'max_timer'},".
                            "$flowParameters{'rslot'}, ".
                            "$flowParameters{'rport'}, ".
                            "$flowParameters{'rvlan'}, ".
                            "$flowParameters{'lslot'}, ".
                            "$flowParameters{'lport'}, ".
                            "$flowParameters{'lvlan'}) ",
                  Timeout => (10),
                  Prompt => "/->|acli-shell:/" )
   
}

sub PPM_NAT_add_flow_loop
{
    my $telnet = "";
    my %sbcInfo = ();
    my %flowParameters = ();
    my %fgParameters = ();
    my $loop = "";
    my $access_type = "";
    
    #pull in variables
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?telnet$/i )
            {
                $telnet = $argument;
            }
            elsif( /^-?info$/i )
            {
                %sbcInfo = %{$argument};
            }
            elsif( /^-?flow$/i )
            {
                %flowParameters = %{$argument};
            }
            elsif( /^-?timers$/i )
            {
                %fgParameters = %{$argument};
            }
            elsif( /^-?access$/i )
            {
                $access_type = $argument;
            }                      
            elsif( /^-?loop$/i )
            {
                $loop = $argument;
            }
        }
    }
    
    #go to shell
    $telnet->print( "" );
    ( $prematch, $match ) = $telnet->waitfor( Match => "/->|acli-shell:/",
                                              Timeout => 1,
                                              Errmode => "return" );
    if( $telnet->errmsg ne "" )
    {
        sdGoToShellPrompt(Session => $telnet, Name => $sbcInfo{'sdname'});
    }
    
    foreach($telnet->cmd( String => "test_CAM_add_flow_loop(".
                            "\"$flowParameters{'rsa'}\", ".
                            "\"$flowParameters{'rda'}\", ".
                            "$flowParameters{'rsp'}, ".
                            "$flowParameters{'rdp'}, ".
                            "\"$flowParameters{'lsa'}\", ".
                            "\"$flowParameters{'lda'}\", ".
                            "$flowParameters{'lsp'}, ".
                            "$flowParameters{'ldp'}, ".
                            "$loop, ".
                            "$access_type)",
                  Timeout => (90),
                  Prompt => "/->|acli-shell:/" ))
    {
        if($_ =~ /value = (\d+)/ )
        {
            return $1;
        }
    }
}

sub PPM_NAT_add_flow_loop_by_DA
{
    my $telnet = "";
    my %sbcInfo = ();
    my %flowParameters = ();
    my %fgParameters = ();
    my $loop = "";
    my $access_type = "";
    
    #pull in variables
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?telnet$/i )
            {
                $telnet = $argument;
            }
            elsif( /^-?info$/i )
            {
                %sbcInfo = %{$argument};
            }
            elsif( /^-?flow$/i )
            {
                %flowParameters = %{$argument};
            }
            elsif( /^-?timers$/i )
            {
                %fgParameters = %{$argument};
            }
            elsif( /^-?access$/i )
            {
                $access_type = $argument;
            }                      
            elsif( /^-?loop$/i )
            {
                $loop = $argument;
            }
        }
    }
    
    #go to shell
    $telnet->print( "" );
    ( $prematch, $match ) = $telnet->waitfor( Match => "/->|acli-shell:/",
                                              Timeout => 1,
                                              Errmode => "return" );
    if( $telnet->errmsg ne "" )
    {
        sdGoToShellPrompt(Session => $telnet, Name => $sbcInfo{'sdname'});
    }
    
    foreach($telnet->cmd( String => "test_CAM_add_flow_loop_by_DA(".
                            "\"$flowParameters{'rsa'}\", ".
                            "\"$flowParameters{'rda'}\", ".
                            "$flowParameters{'rsp'}, ".
                            "$flowParameters{'rdp'}, ".
                            "\"$flowParameters{'lsa'}\", ".
                            "\"$flowParameters{'lda'}\", ".
                            "$flowParameters{'lsp'}, ".
                            "$flowParameters{'ldp'}, ".
                            "$loop, ".
                            "$access_type)",
                  Timeout => (90),
                  Prompt => "/->|acli-shell:/" ))
    {
        if($_ =~ /value = (\d+)/ )
        {
            return $1;
        }
    }
}

sub PPM_NAT_verify_flow
{
    my $telnet = "";
    my %sbcInfo = ();
    my $flowID = "";
    
    #pull in variables
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?telnet$/i )
            {
                $telnet = $argument;
            }
            elsif( /^-?info$/i )
            {
                %sbcInfo = %{$argument};
            }
            elsif( /^-?flowID$/i )
            {
                $flowID = $argument;
            }              
        }
    }
    
    #go to shell
    $telnet->print( "" );
    ( $prematch, $match ) = $telnet->waitfor( Match => "/->|acli-shell:/",
                                              Timeout => 1,
                                              Errmode => "return" );
    if( $telnet->errmsg ne "" )
    {
        sdGoToShellPrompt(Session => $telnet, Name => $sbcInfo{'sdname'});
    }
    
    foreach($telnet->cmd( String => "PPX_verify_flowID(".
                                    "$flowID)",
                          Timeout => (10),
                          Prompt => "/->|acli-shell:/" ))
    {
        if($_ =~ /value = (\d+)/ )
        {
            if($1 != 0)
            {
                return 1;
            }
            last;
        }
    }
    return 0;
}

sub PPM_NAT_verify_flow_exist_loop
{
    my $telnet = "";
    my %sbcInfo = ();
    my $first_flowID = "";
    my $loop = "";
    
    #pull in variables
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?telnet$/i )
            {
                $telnet = $argument;
            }
            elsif( /^-?info$/i )
            {
                %sbcInfo = %{$argument};
            }
            elsif( /^-?first_flowID$/i )
            {
                $first_flowID = $argument;
            }              
            elsif( /^-?loop$/i )
            {
                $loop = $argument;
            }
        }
    }
    
    #go to shell
    $telnet->print( "" );
    ( $prematch, $match ) = $telnet->waitfor( Match => "/->|acli-shell:/",
                                              Timeout => 1,
                                              Errmode => "return" );
    if( $telnet->errmsg ne "" )
    {
        sdGoToShellPrompt(Session => $telnet, Name => $sbcInfo{'sdname'});
    }
    
    foreach($telnet->cmd( String => "PPX_verify_flowID_exist_loop(".
                                    "$first_flowID, ".
                                    "$loop)",
                          Timeout => (10),
                          Prompt => "/->|acli-shell:/" ))
    {
        if($_ =~ /value = (\d+)/ )
        {
            if($1 != 0)
            {
                return 1;
            }
            last;
        }
    }
    return 0;
}

sub PPM_NAT_verify_flow_destroy_loop
{
    my $telnet = "";
    my %sbcInfo = ();
    my $first_flowID = "";
    my $loop = "";
    
    #pull in variables
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?telnet$/i )
            {
                $telnet = $argument;
            }
            elsif( /^-?info$/i )
            {
                %sbcInfo = %{$argument};
            }
            elsif( /^-?first_flowID$/i )
            {
                $first_flowID = $argument;
            }              
            elsif( /^-?loop$/i )
            {
                $loop = $argument;
            }
        }
    }
    
    #go to shell
    $telnet->print( "" );
    ( $prematch, $match ) = $telnet->waitfor( Match => "/->|acli-shell:/",
                                              Timeout => 1,
                                              Errmode => "return" );
    if( $telnet->errmsg ne "" )
    {
        sdGoToShellPrompt(Session => $telnet, Name => $sbcInfo{'sdname'});
    }
    
    foreach($telnet->cmd( String => "PPX_verify_flowID_destroy_loop(".
                                    "$first_flowID, ".
                                    "$loop)",
                          Timeout => (10),
                          Prompt => "/->|acli-shell:/" ))
    {
        if($_ =~ /value = (\d+)/ )
        {
            if($1 != 0)
            {
                return 1;
            }
            last;
        }
    }
    return 0;
}

sub PPM_NAT_delete_flow
{
    my $telnet = "";
    my %sbcInfo = ();
    my $flowID = "";
    
    #pull in variables
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?telnet$/i )
            {
                $telnet = $argument;
            }
            elsif( /^-?info$/i )
            {
                %sbcInfo = %{$argument};
            }
            elsif( /^-?flowID$/i )
            {
                $flowID = $argument;
            }              
        }
    }
    
    #go to shell
    $telnet->print( "" );
    ( $prematch, $match ) = $telnet->waitfor( Match => "/->|acli-shell:/",
                                              Timeout => 1,
                                              Errmode => "return" );
    if( $telnet->errmsg ne "" )
    {
        sdGoToShellPrompt(Session => $telnet, Name => $sbcInfo{'sdname'});
    }
    
    $telnet->cmd( String => "test_CAM_delete_flow(".
                            "$flowID)",
                  Timeout => (10),
                  Prompt => "/->|acli-shell:/" );  
}

sub PPM_NAT_delete_flow_loop
{
    my $telnet = "";
    my %sbcInfo = ();
    my $first_flowID = "";
    my $loop = "";
    
    #pull in variables
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?telnet$/i )
            {
                $telnet = $argument;
            }
            elsif( /^-?info$/i )
            {
                %sbcInfo = %{$argument};
            }
            elsif( /^-?first_flowID$/i )
            {
                $first_flowID = $argument;
            }              
            elsif( /^-?loop$/i )
            {
                $loop = $argument;
            }
        }
    }
    
    #go to shell
    $telnet->print( "" );
    ( $prematch, $match ) = $telnet->waitfor( Match => "/->|acli-shell:/",
                                              Timeout => 1,
                                              Errmode => "return" );
    if( $telnet->errmsg ne "" )
    {
        sdGoToShellPrompt(Session => $telnet, Name => $sbcInfo{'sdname'});
    }
    
    $telnet->cmd( String => "test_CAM_delete_loop(".
                            "$first_flowID, ".
                            "$loop)",
                  Timeout => (60),
                  Prompt => "/->|acli-shell:/" );  
}

sub expand_IP_addr
{
    my $ip = "";

    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?ip_addr$/i )
            {
                $ip = $argument;
            }
        }
    }

    if(ip_is_ipv6($ip))
    {
        $ip = ip_expand_address($ip, 6);
    }
    elsif(ip_is_ipv4($ip))
    {
        $ip = ip_expand_address($ip, 4);
    }
    else
    {
        log_msg("ERROR: not a valid IP address\n");
    }
    
    return $ip;
}
sub increment_IP_addr_v4
{   
    my $a = "";
    my $b = "";
    my $c = "";
    my $d = "";
    
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?ip_addr$/i )
            {
                $ip = $argument;
            }
        }
    }
    
    if($ip =~ m/^(\d+).(\d+).(\d+).(\d+)$/)
    {
        $a = $1;
        $b = $2;
        $c = $3;
        $d = $4;
    }
    
    #increment IP address
    if($d < 254)
    {
        $d++;
    }
    else
    {
        $d = 1;
        if($c < 254)
        {
            $c++;
        }
        else
        {
            $c = 1;
            if($b < 254)
            {
                $b++;
            }
            else
            {
                $b = 1;
                if($a < 254)
                {
                    $a++;
                }
                else
                {
                    $a = 1;   
                }
            }
        }         
    }
    
    return "$a.$b.$c.$d";    
}

sub increment_IP_addr_v4_2
{   
    my $a = "";
    my $b = "";
    my $c = "";
    my $d = "";
    my $amt = "";
    my $mod = "";
    my %div = "";
    my $ip = "";
    
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?ip_addr$/i )
            {
                $ip = $argument;
            }
            elsif( /^-?amt$/i )
            {
                $amt = $argument;
            }
        }
    }
    
    $mod = $amt % 254;
    $div = floor($amt / 254);
       
    if($ip =~ m/^(\d+).(\d+).(\d+).(\d+)$/)
    {
        $a = $1;
        $b = $2;
        $c = $3;
        $d = $4;
    }
    
    #increment IP address
    $c += $div;
    $d += $mod;
    
    #adjust IP address
    if($d > 254)
    {
        $d -= 254;
        $c += 1;
    }
    if($c > 254)
    {
        $c -= 254;
        $b += 1;
    }
    if($b > 254)
    {
        $b -= 254;
        $a += 1;
    }
    if($a > 254)
    {
        $a -= 254;
    }

    return "$a.$b.$c.$d";    
}

sub increment_IP_addr_v6
{   
    my $a = "";
    my $b = "";
    my $c = "";
    my $d = "";
    my $e = "";
    my $f = "";
    my $g = "";
    my $h = "";
    my $ip = "";
    
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?ip_addr$/i )
            {
                $ip = $argument;
            }
        }
    }
    
    #grab variables, works with hex values
    if($ip =~ m/^([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+)$/)
    {
        $a = hex($1);
        $b = hex($2);
        $c = hex($3);
        $d = hex($4);
        $e = hex($5);
        $f = hex($6);
        $g = hex($7);
        $h = hex($8);     
    }
    
    #increment IP address
    if($h < 0xFFFF)
    {
        $h++;
    }
    else
    {
        $h = 1;
        if($g < 0xFFFF)
        {
            $g++;
        }
        else
        {
            $g = 1;
            if($f < 0xFFFF)
            {
                $f++;
            }
            else
            {
                $f = 1;
                if($e < 0xFFFF)
                {
                    $e++;
                }
                else
                {
                    $e = 1;
                    if($d < 0xFFFF)
                    {
                        $d++;
                    }
                    else
                    {
                        $d = 1;
                        if($c < 0xFFFF)
                        {
                            $c++;
                        }
                        else
                        {
                            $c = 1;
                            if($b < 0xFFFF)
                            {
                                $b++;
                            }
                            else
                            {
                                $b = 1;
                                if($a < 0xFFFF)
                                {
                                    $a++;
                                }
                                else
                                {
                                    $a = 1;
                                }
                             }
                        }
                    }
                }
            }
        }         
    }
    return expand_IP_addr(IP_addr => sprintf("%x:%x:%x:%x:%x:%x:%x:%x", $a,$b,$c,$d,$e,$f,$g,$h));
}

sub increment_IP_addr_v6_2
{   
    my $a = "";
    my $b = "";
    my $c = "";
    my $d = "";
    my $e = "";
    my $f = "";
    my $g = "";
    my $h = "";
    my $ip = "";
    my $amt = "";
    
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?ip_addr$/i )
            {
                $ip = $argument;
            }
            elsif( /^-?amt$/i )
            {
                $amt = $argument;
            }
        }
    }

    #grab variables
    if($ip =~ m/^([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+)$/)
    {
        $a = $1;
        $b = $2;
        $c = $3;
        $d = $4;
        $e = $5;
        $f = $6;
        $g = $7;
        $h = $8;     
    }

    #increment IP address and convert to decimal
    $h = hex($h) + $amt;   
    $g = hex($g);
    $f = hex($f);
    $e = hex($e);
    $d = hex($d);
    $c = hex($c);
    $b = hex($b);
    $a = hex($a);
        
    #adjust IP address
    while($h > 0xFFFF)
    {
        $h -= 0xFFFF;
        $g += 1;
    }
    while($g > 0xFFFF)
    {
        $g -= 0xFFFF;
        $f += 1;
    }
    while($f > 0xFFFF)
    {
        $f -= 0xFFFF;
        $e += 1;
    }
    while($e > 0xFFFF)
    {
        $e -= 0xFFFF;
        $d += 1;
    }
    while($d > 0xFFFF)
    {
        $d -= 0xFFFF;
        $c += 1;
    }
    while($c > 0xFFFF)
    {
        $c -= 0xFFFF;
        $b += 1;
    }
    while($b > 0xFFFF)
    {
        $b -= 0xFFFF;
        $a += 1;
    }
    while($a > 0xFFFF)
    {
        $a -= 0xFFFF;
        $h += 1;
    }
    
    #convert back to hex values
    $a =~ s/(.+)/sprintf("%x",$1)/eg;
    $b =~ s/(.+)/sprintf("%x",$1)/eg;
    $c =~ s/(.+)/sprintf("%x",$1)/eg;
    $d =~ s/(.+)/sprintf("%x",$1)/eg;
    $e =~ s/(.+)/sprintf("%x",$1)/eg;
    $f =~ s/(.+)/sprintf("%x",$1)/eg;
    $g =~ s/(.+)/sprintf("%x",$1)/eg;
    $h =~ s/(.+)/sprintf("%x",$1)/eg;
    
    return expand_IP_addr(IP_addr => "$a:$b:$c:$d:$e:$f:$g:$h");
}

sub increment_IP_addr
{   
    my $ip = "";
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?ip_addr$/i )
            {
                $ip = $argument;
            }
        }
    }
    if(ip_is_ipv6($ip))
    {
        $ip = increment_IP_addr_v6(IP_addr =>  $ip);
    }
    elsif(ip_is_ipv4($ip))
    {
        $ip = increment_IP_addr_v4(IP_addr =>  $ip);
    }
    return $ip;     
}

sub increment_IP_addr_2
{   
    my $ip = "";
    my $amt = "";
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?ip_addr$/i )
            {
                $ip = $argument;
            }
            elsif( /^-?amt$/i )
            {
                $amt = $argument;
            }
        }
    }
    
    if(ip_is_ipv6($ip))
    {
        $ip = increment_IP_addr_v6_2(IP_addr =>  $ip,
                                     Amt => $amt);
    }
    elsif(ip_is_ipv4($ip))
    {
        $ip = increment_IP_addr_v4_2(IP_addr =>  $ip,
                                     Amt => $amt);
    }
    return $ip;     
}
     
sub get_num_shuffles
{
    my $telnet = "";
    my %sbcInfo = ();
    my $shuffles = "";
    my @output = ();
    
    #pull in variables
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?telnet$/i )
            {
                $telnet = $argument;
            }
            elsif( /^-?info$/i )
            {
                %sbcInfo = %{$argument};
            }            
        }
    }
    
    #go to shell
    $telnet->print( "" );
    ( $prematch, $match ) = $telnet->waitfor( Match => "/->|acli-shell:/",
                                              Timeout => 1,
                                              Errmode => "return" );
    if( $telnet->errmsg ne "" )
    {
        sdGoToShellPrompt(Session => $telnet, Name => $sbcInfo{'sdname'});
    }
    
    @output = $telnet->cmd( String => "natStatsShow()",
                          Timeout => (10),
                          Prompt => "/->|acli-shell:/" );
    #parse output
    foreach(@output)
    {
        if($_ =~ m/count_shuffles\s+(\d+)/i)
        {
            $shuffles = $1;
        }
    }
    
    return $shuffles;
}            
            
            
            
            
            
            
