#!/usr/bin/perl

package Acme::dos2testlib;

use Acme::embtestlib;
use Acme::ip;
use Exporter;
use Net::Telnet;
use Switch;
use POSIX;

our @ISA = qw( Exporter );

# these can be exported.
our @EXPORT_OK = qw( sd_listener_send_rtp_packets PPM_NAT_add_flow PPM_NAT_add_flow2 PPM_NAT_config_flow PPM_NAT_add_flow_loop PPM_NAT_add_flow_loop_rand PPM_NAT_add_flow_loop_by_DA PPM_NAT_verify_flow PPM_NAT_verify_flow_exist_loop PPM_NAT_verify_flow_destroy_loop PPM_NAT_delete_flow PPM_NAT_delete_flow_loop increment_IP_addr increment_IP_addr_v4 increment_IP_addr_v6 get_num_shuffles increment_IP_addr_v4_2 increment_IP_addr_v6_2 increment_IP_addr_2 expand_IP_addr get_analyzeDOS2HashTables_info random_IP get_aclShowSummary expire_flow expire_flow_loop ip_addr_checker);

# these are exported by default
our @EXPORT = qw( sd_listener_send_rtp_packets PPM_NAT_add_flow PPM_NAT_add_flow2 PPM_NAT_config_flow PPM_NAT_add_flow_loop PPM_NAT_add_flow_loop_rand PPM_NAT_add_flow_loop_by_DA PPM_NAT_verify_flow PPM_NAT_verify_flow_exist_loop PPM_NAT_verify_flow_destroy_loop PPM_NAT_delete_flow PPM_NAT_delete_flow_loop increment_IP_addr increment_IP_addr_v4 increment_IP_addr_v6 get_num_shuffles increment_IP_addr_v4_2 increment_IP_addr_v6_2 increment_IP_addr_2 expand_IP_addr get_analyzeDOS2HashTables_info random_IP get_aclShowSummary expire_flow expire_flow_loop ip_addr_checker);

#globals
our $last_ipv4 = qw(1.1.1.1);
our $last_ipv6 = qw(0001:0001:0001:0001:0001:0001:0001:0001);

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
    my $last32 = 0;
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
            elsif( /^-?last32$/i )
            {
                $last32 = $argument;
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
    
    if($last32 == 0){
    
        $telnet->cmd( String => "spawn_test_CAM_add_flow_loop(".
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
                      Timeout => (300),
                      Prompt => "/->|acli-shell:/" );
                                   
        ( $prematch, $match ) = $telnet->waitfor(Match => "/First Flow ID:.+/",
                                                   Timeout => 1,
                                                   Errmode => "return" );
                      
                              
        if($match =~ m/First Flow ID: (\d+)/i )
        {
            return $1;
        }
    
    }else{
    
        $telnet->cmd( String => "spawn_test_CAM_add_flow_loop_last32(".
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
                      Timeout => (300),
                      Prompt => "/->|acli-shell:/" );
        
        ( $prematch, $match ) = $telnet->waitfor(Match => "/First Flow ID:.+/",
                                                   Timeout => 1,
                                                   Errmode => "return" );
                      
                              
        if($match =~ m/First Flow ID: (\d+)/i )
        {
            return $1;
        }
        
        
   }
}

sub PPM_NAT_add_flow_loop_rand
{
    my $telnet = "";
    my %sbcInfo = ();
    my %flowParameters = ();
    my %fgParameters = ();
    my $loop = "";
    my $access_type = "";
    my $last32 = 0;
    
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
            elsif( /^-?last32$/i )
            {
                $last32 = $argument;
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
    
    if($last32 == 0){
    
        $telnet->cmd( String => "spawn_test_CAM_add_flow_loop_rand(".
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
                      Timeout => (300),
                      Prompt => "/->|acli-shell:/" );
        
        ( $prematch, $match ) = $telnet->waitfor(Match => "/First Flow ID:.+/",
                                                   Timeout => 1,
                                                   Errmode => "return" );
                                            
        if($match =~ m/First Flow ID: (\d+)/i )
        {
            return $1;
        }
        
    }else{
        
        $telnet->cmd( String => "spawn_test_CAM_add_flow_loop_rand_last32(".
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
                      Timeout => (300),
                      Prompt => "/->|acli-shell:/" );
        
        ( $prematch, $match ) = $telnet->waitfor(Match => "/First Flow ID:.+/",
                                                   Timeout => 1,
                                                   Errmode => "return" );
                                                   
        if($match =~ m/First Flow ID: (\d+)/i )
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
    
    $telnet->cmd( String => "spawn_test_delete_loop(".
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
                    if($d< 0xFFFF)
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
    
    return expand_IP_addr(IP_addr => sprintf("%x:%x:%x:%x:%x:%x:%x:%x",$a,$b,$c,$d,$e,$f,$g,$h));
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
    my $last32 = 0;
    
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
            elsif( /^-?last32$/i )
            {
                $last32 = $argument;
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
    if($last32 != 0){
        $h = hex($h);
        $g = hex($g);
        $f = hex($f) + $amt;
    }else{
        $h = hex($h) + $amt;
        $g = hex($g);
        $f = hex($f);
    }
    
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
    my $last32 = 0;
    my $mixed_traffic = 0;
    my $temp = "";
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
            elsif( /^-?last32$/i )
            {
                $last32 = $argument;
            }
            elsif( /^-?mixed_traffic$/i )
            {
                $mixed_traffic = $argument;
            }
        }
    }
    
    #if we are using mixed traffic, we are alternating ipv4/v6 addresses
    #remember this addr for next time and use last known ipv4/v6 address
    if($mixed_traffic != 0){
        if( ip_is_ipv6($ip) ){
            $last_ipv6 = $ip;
            $ip = $last_ipv4;
        }else{
            $last_ipv4 = $ip;
            $ip = $last_ipv6;
        }
    }
    
    if( ip_is_ipv6($ip) )
    {
        $ip = increment_IP_addr_v6_2(IP_addr =>  $ip,
                                     Amt => $amt,
                                     Last32 => $last32);
    }
    else
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
            
sub get_analyzeDOS2HashTables_info
{
    my $telnet = "";
    my %sbcInfo = ();
    my $shuffles = "";
    my @output = ();
    my @hash_indexes_by_element_num22 = ();
    my @hash_indexes_by_element_num23 = ();
    my @hash_indexes_by_depth_num22 = ();
    my @hash_indexes_by_depth_num23 = ();
    
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
    
    @output = $telnet->cmd( String => "analyzeDOS2HashTables",
                          Timeout => (10),
                          Prompt => "/->|acli-shell:/" );
  
    
    #split into 2 arrays
    my $i = 0;
    my $split = "";
    my $len = @output;
    foreach(@output)
    {
        if($_ =~ m/Searching Hash Table 23/i)
        {
            $split = $i;
            last;
        }
        $i++;
    }
    @hashtable22 = @output[0..$split-1];
    @hashtable23 = @output[$split..$len];

    #parse array
    foreach(@hashtable22){
        if($_ =~ m/number of hash indexes\s+(\d+)/i){
            log_msg("Hashtable22: Number of hash indexes: $1\n");
        }
        if($_ =~ m/num_used_buckets\s+(\d+)/i){
            log_msg("Hashtable22: Number of used buckets: $1\n");
        }
        if($_ =~ m/num_empty_buckets\s+(\d+)/i){
            log_msg("Hashtable22: Number of empty buckets: $1\n");
        }
        for($i = 0; $i < 16; $i++){
            if($_ =~ m/Hash Indexes with\s+$i\s+elements:\s+(\d+)/i){
                push(@hash_indexes_by_element_num22, $1);
            }
        }
        for($i = 0; $i < 6; $i++){
            if($_ =~ m/Hash Indexes with\s+$i\s+overflow depth:\s+(\d+)/i){
                push(@hash_indexes_by_depth_num22, $1);
            }
        }
    }
    foreach(@hashtable23){
        if($_ =~ m/number of hash indexes\s+(\d+)/i){
            log_msg("Hashtable23: Number of hash indexes: $1\n");
        }
        if($_ =~ m/num_used_buckets\s+(\d+)/i){
            log_msg("Hashtable23: Number of used buckets: $1\n");
        }
        if($_ =~ m/num_empty_buckets\s+(\d+)/i){
            log_msg("Hashtable23: Number of empty buckets: $1\n");
        }
        for($i = 0; $i < 16; $i++){
            if($_ =~ m/Hash Indexes with\s+$i\s+elements:\s+(\d+)/i){
                push(@hash_indexes_by_element_num23, $1);
            }
        }
        for($i = 0; $i < 6; $i++){
            if($_ =~ m/Hash Indexes with\s+$i\s+overflow depth:\s+(\d+)/i){
                push(@hash_indexes_by_depth_num23, $1);
            }
        }
    }
}                  

sub random_IP
{
    my $a = "";
    my $b = "";
    my $c = "";
    my $d = "";
    my $e = "";
    my $f = "";
    my $g = "";
    my $h = "";
    my $last32 = 0;
    my $mixed_traffic = 0;
    
    if( @_ > 0 && ( @_ % 2 ) == 0 )
    {
        while( ( $_, $argument ) = splice( @_, 0, 2 ) )
        {
            if( /^-?ip_addr$/i )
            {
                $ip = $argument;
            }
            elsif( /^-?last32$/i )
            {
                $last32 = $argument;
            }
            elsif( /^-?mixed_traffic$/i )
            {
                $mixed_traffic = $argument;
            }           
        }
    }
    #if we are using mixed traffic, we are alternating ipv4/v6 addresses
    #remember this addr for next time and use last known ipv4/v6 address
    if($mixed_traffic != 0){
        if( ip_is_ipv6($ip) ){
            $last_ipv6 = $ip;
            $ip = $last_ipv4;
        }else{
            $last_ipv4 = $ip;
            $ip = $last_ipv6;
        }
    }

    if( ip_is_ipv6($ip) )
    {
        #keep last 32 bits if variable is true
        if($last32 == 1){
            if($ip =~ m/^[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+:([0-9a-fA-F]+):([0-9a-fA-F]+)$/)
            {
                #grab the last 32 bits of the IPv6 address to preserve them
                $g = $1;
                $h = $2;
            }
        }else{
            $g = int(rand(65534)) + 1;
            $h = int(rand(65534)) + 1;
        }
        
        $a = int(rand(65534)) + 1;
        $b = int(rand(65534)) + 1;
        $c = int(rand(65534)) + 1;
        $d = int(rand(65534)) + 1;
        $e = int(rand(65534)) + 1;
        $f = int(rand(65534)) + 1;
    
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
    else
    {   
        $a = int(rand(254)) + 1;
        $b = int(rand(254)) + 1;
        $c = int(rand(254)) + 1;
        $d = int(rand(254)) + 1;
        
        #remember last ip addresses
        if( ip_is_ipv6($ip) ){
            $last_ipv6 = $ip;
        }else{
            $last_ipv4 = $ip;
        }
        
        return "$a.$b.$c.$d";
    } 

}            
            
sub get_aclShowSummary
{
    my $telnet = "";
    my %sbcInfo = ();
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
    $telnet->cmd( String => "acli_pre_get()",
                          Timeout => (10),
                          Prompt => "/->|acli-shell:/" );
    
    @output = $telnet->cmd( String => "aclShowSummary()",
                          Timeout => (10),
                          Prompt => "/->|acli-shell:/" );
                          
    $telnet->cmd( String => "acli_post_get()",
                          Timeout => (10),
                          Prompt => "/->|acli-shell:/" );
    
    return @output;
}

sub expire_flow
{
    my $telnet = "";
    my %sbcInfo = ();
    my $flowID = "";
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
            elsif( /^-?flowid$/i )
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
    
    @output = $telnet->cmd( String => "test_ppx_flow_change_max_timer($flowID,0)",
                              Timeout => (10),
                              Prompt => "/->|acli-shell:/" );            
           
    return @output;
}

sub expire_flow_loop
{
    my $telnet = "";
    my %sbcInfo = ();
    my $loop = "";
    my $flowID = "";
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
            elsif( /^-?loop$/i )
            {
                $loop = $argument;
            }
            elsif( /^-?flowid$/i )
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
    
    @output = $telnet->cmd( String => "test_ppx_flow_change_max_timer_loop($flowID,0,$loop)",
                              Timeout => (10),
                              Prompt => "/->|acli-shell:/" );            
           
    return @output;
}

sub ip_addr_checker
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
        $ip = ip_addr_checker_v6(IP_addr =>  $ip);
    }
    elsif(ip_is_ipv4($ip))
    {
        $ip = ip_addr_checker_v4(IP_addr =>  $ip);
    }
    
    return $ip;    
}

sub ip_addr_checker_v4
{   
    my $a = "";
    my $b = "";
    my $c = "";
    my $d = "";
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
       
    if($ip =~ m/^(\d+).(\d+).(\d+).(\d+)$/)
    {
        $a = $1;
        $b = $2;
        $c = $3;
        $d = $4;
    }
    
    if($a == 0 || $a >= 255){
        $a = 1;
    }
    if($b == 0 || $b >= 255){
        $b = 1;
    }
    if($c == 0 || $c >= 255){
        $c = 1;
    }
    if($d == 0 || $d >= 255){
        $d = 1;
    }
    
    return "$a.$b.$c.$d";    
}

sub ip_addr_checker_v6
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
    
    if($a == 0 || $a >= 0xFFFF){
        $a = 1;
    }
    if($b == 0 || $b >= 0xFFFF){
        $b = 1;
    }
    if($c == 0 || $c >= 0xFFFF){
        $c = 1;
    }
    if($d == 0 || $d >= 0xFFFF){
        $d = 1;
    }
    if($e == 0 || $e >= 0xFFFF){
        $e = 1;
    }
    if($f == 0 || $f >= 0xFFFF){
        $f = 1;
    }
    if($g == 0 || $g >= 0xFFFF){
        $g = 1;
    }
    if($h == 0 || $h >= 0xFFFF){
        $h = 1;
    }
       
    return expand_IP_addr(IP_addr => sprintf("%x:%x:%x:%x:%x:%x:%x:%x",$a,$b,$c,$d,$e,$f,$g,$h));
}
