#!/usr/bin/perl -w

use strict;
use warnings;
use Acme::embtestlib;
use Errno;
use autodie qw(:default);
use feature "switch";
use DBI;

use constant MAX_SCRIPT_RUNNING_SECONDS => 60;
use constant MAX_RESERVE_TIME => 420; # Give 7 minutes til the mirror needs to be cleaned up
use constant MAX_PCAP_DURATION => 300; # Longest time a pcap should collect for

my $embtest_root_dir     = ROOT;
my $embedded_network_dir = $embtest_root_dir . "/embedded_network";
my $script_running_file  = $embedded_network_dir . "/script.running";
my $db_host              = DB_HOST;
my $db_user              = DB_USER;
my $db_pass              = DB_PASS;
my $database             = DB_DATABASE;
my $db_entry;
my $debug                = 0;
my $do_cleanup           = 1;
my @config_files         = ();
my $q                    = "";
my $child_process        = 0;
my @child_pids           = ();
my %switches;


#log_msg("Root: $embtest_root_dir, Embedded Network Dir: $embedded_network_dir");

if(-e $script_running_file)
{
    # Let us check the PID stored within the script.running file corresponds to an existing process
    open(my $fh, "<", $script_running_file) or die "Cannot open file $script_running_file: $!";

    my $script_running_pid = <$fh>;
    chomp $script_running_pid;

    if((kill 0, $script_running_pid) == 0)
    {
        log_msg("embedded_network.pl process is no longer running but script.running file still exists.", "ERROR");
        log_msg("Assuming prior script process was incorrectly terminated and deleting script.running file", "ERROR");
        unlink $script_running_file;
    }
    else
    {
        log_msg("Script is currently running, will try again later", "INFO");
        $do_cleanup = 0;
        exit 0;
    }
}
#log_msg("");

# Create script.running file to prevent concurrent executions of this script
open(my $fh, ">>", $script_running_file) or die "Cannot open file: $!";
print $fh $$;
close $fh;

# Iterate over embedded_network directory pulling out all valid .config files
opendir(my $dh, $embedded_network_dir) or die $!;

my @files = (sort readdir($dh));
while(my $file = shift @files)
{
    if($file =~ m/\.config$/)
    {
        push(@config_files, $embedded_network_dir . "/" . $file);
    }
    else
    {
        # Don't care about anything else
        next;
    }
}

closedir($dh);

#Connect to DB 
#log_msg("Host: $db_host, User: $db_user, Pass: $db_pass, Database: $database");
#log_msg("");
my $db_handle = DBI->connect("DBI:mysql:$database:$db_host", $db_user, $db_pass,{ RaiseError => 1,  })
                or die "connect: cannot connect to database: $DBI::errstr";

$q = "SELECT id, ip, login, password FROM embedded_network_switches WHERE 1";
$db_entry = $db_handle->prepare($q);
$db_entry->execute;

while(my $hash_ref = $db_entry->fetchrow_hashref)
{
    $switches{$hash_ref->{id}} = $hash_ref;
    @{$switches{$hash_ref->{id}}{configs}} = ();
    @{$switches{$hash_ref->{id}}{mirrors}} = ();

    $q = "SELECT mirror_name, reserve_time, start_time, duration_seconds, server_ip, server_interface";
    $q .= " FROM embedded_network_mirrors";
    $q .= " WHERE mirror_switch_id = $hash_ref->{id} AND reserve_time IS NOT NULL";
    my $mirror_db_entry = $db_handle->prepare($q);
    $mirror_db_entry->execute;

    while(my $mirror_hash_ref = $mirror_db_entry->fetchrow_hashref)
    {
        push(@{$switches{$hash_ref->{id}}{mirrors}}, \%{$mirror_hash_ref});
    }

    #log_msg("Adding Switch to hash:");
    foreach my $var (keys %{$switches{$hash_ref->{id}}})
    {
        #log_msg("$var: $switches{$hash_ref->{id}}{$var}");
    }
    #log_msg("");

}

#log_msg("Config files being processed:");
#log_msg("@config_files");
#log_msg("");

foreach (@config_files) {
    my %hash;
    my $temp_id = 0;

    $hash{FILE_NAME} = $_;

    open(my $file, $_);
    while(<$file>)
    {
        chomp;
        if($_ =~ m/END/)
        {
            last;
        }

        my ($key, $value) = split('=', $_);

        if($key =~ m/SWITCH_ID/)
        {
            $temp_id = $value;
        }
        else
        {
            $hash{$key} = $value;
        }
    }

    close($file);

    if($temp_id != 0)
    {
        if(exists $switches{$temp_id})
        {
            push(@{$switches{$temp_id}{configs}}, \%hash);
            
            #log_msg("Adding hash to configs array for switch: $temp_id");
            foreach my $var (keys %hash)
            {
                #log_msg("$var: $hash{$var}");
            }
            #log_msg("");
        }
        else
        {
            log_msg("Attempting to add a config file to an invalid switch id.", "ERROR");
        }
    }
}

foreach my $key (keys %switches)
{
    my $pid = 0;

    $pid = fork();
    if($pid)
    {
       # Parent Process
       #log_msg("Forking child instance for switch: $switches{$key}{id}");
       push(@child_pids, $pid);
    }
    else
    {
        # Child Process
        my $switch_main_prompt = '/[A-Za-z]+-[0-9]+ [A-Za-z]+\.[0-9]+ #/';
        my $prematch = "";
        my $match = "";
        my $do_save = 0;

        $child_process = 1;

        #NBT - rather than fork then check and exit, we should probably 
        #----- check if we need to fork first?

        if((scalar @{$switches{$key}{configs}} == 0)
            && (scalar @{$switches{$key}{mirrors}} == 0))
        {
            #Uncomment for debug. This thing spams x5 every 3 seconds.
#            log_msg("This switch has no configuration files or mirrors needing to be processed. Exiting...", "CHILD $key");
            exit 0;
        }

        my $db_handle = DBI->connect("DBI:mysql:$database:$db_host", $db_user, $db_pass,{ RaiseError => 1,  })
            or die "connect: cannot connect to database: $DBI::errstr";

        my $session = Net::Telnet->new(Host => $switches{$key}{ip});
        $session->input_log(*STDOUT);

        $session->print("");
        ($prematch, $match) = $session->waitfor(Match => '/login:/');
        $session->print("$switches{$key}{login}");
        ($prematch, $match) = $session->waitfor(Match => '/password:/');
        $session->print("$switches{$key}{password}");
        ($prematch, $match) = $session->waitfor(Match => $switch_main_prompt);

        # Lets check to see how port mirrors are doing.
        foreach(@{$switches{$key}{mirrors}})
        {
            my %hash = %{$_};
            my $current_time = time();

            if((defined($hash{start_time}) && ($current_time > $hash{start_time} + $hash{duration_seconds} + 10))
                || (defined($hash{reserve_time}) && ($current_time > $hash{reserve_time} + MAX_RESERVE_TIME)))
            {

                #if($hash{start_time} && ($current_time > $hash{start_time} + $hash{duration_seconds}))
                #{
                #    log_msg("start: $hash{start_time}, current: $current_time, duration: $hash{duration_seconds}");
                #}
                #elsif($hash{reserve_time} && ($current_time > $hash{reserve_time} + MAX_RESERVE_TIME))
                #{
                #    log_msg("reserve: $hash{reserve_time}, current: $current_time, max: 420");
                #}
                #else
                #{
                #    log_msg("Not sure...");
                #}

                # Time to turn this port mirror off
                log_msg("Removing ports from the mirror: $hash{mirror_name}", "CHILD $key");
                $session->print("configure mirror $hash{mirror_name} delete all");
                ($prematch, $match) = $session->waitfor(Match => $switch_main_prompt);

                $q = "UPDATE embedded_network_mirrors AS t1";
                $q .= " SET t1.reserve_time = NULL";
                $q .= ", t1.start_time = NULL";
                $q .= ", t1.duration_seconds = NULL";
                $q .= " WHERE t1.mirror_name = '$hash{mirror_name}'";
                $q .= " LIMIT 1";
                # log_msg("Query: $q", "CHILD $key");
                my $mirror_db_entry = $db_handle->prepare($q);
                $mirror_db_entry->execute;

                $do_save = 1;
            }

            # Print out the mirror information
            foreach my $var (keys %hash)
            {
                if($hash{$var})
                {
                    #log_msg("$var: $hash{$var}", "CHILD $key");
                }
            }
        }

        if(scalar @{$switches{$key}{configs}} != 0)
        {
            log_msg("Processing configs files for switch: $switches{$key}{id}", "CHILD $key");
            foreach (@{$switches{$key}{configs}})
            {
                #Nick: I added the foreach to print this line rather than a hash reference.
                #----: Still no idea what Scott actually was trying to print here. The filename doesn't give us much info.
                log_msg("Config File: $_->{FILE_NAME}", "CHILD $key");
            }
        }

        foreach(@{$switches{$key}{configs}})
        {
            my %hash = %{$_};
            if($hash{ACTION} =~ m/add-port/)
            {
                $session->print("show port $hash{PORT} no-refresh | include $hash{PORT}");
                ($prematch, $match) = $session->waitfor(Match => $switch_main_prompt);

                if($hash{TYPE} =~ m/untagged/)
                {
                    my @results = $session->cmd(String => "show port $hash{PORT} no-refresh | include $hash{PORT}",
                        Timeout => 10,
                        Prompt => $switch_main_prompt);
                    foreach(@results)
                    {
                        if($_ =~ /$hash{PORT}/)
                        {
                            chomp;
                            my @split = split(/\s+/, $_);

                            if((@split > 2))
                            {
                                if($split[2] =~ m/[a-z]+-[a-z0-9]+/)
                                {
                                    log_msg("Removing VMAN $split[2] from port $hash{PORT}", "CHILD $key");
                                    $session->print("configure vman $split[2] delete ports $hash{PORT}");
                                    ($prematch, $match) = $session->waitfor(Match => $switch_main_prompt);
                                    last;
                                }
                            }
                        }
                    }
                }

                $session->print("configure vman $hash{VMAN_NAME} add ports $hash{PORT} $hash{TYPE}");
                ($prematch, $match) = $session->waitfor(Match => $switch_main_prompt);
            }
            elsif($hash{ACTION} =~ m/delete-port/)
            {
                $session->print("show port $hash{PORT} no-refresh | include $hash{PORT}");
                ($prematch, $match) = $session->waitfor(Match => $switch_main_prompt);

                $session->print("configure vman $hash{VMAN_NAME} delete ports $hash{PORT}");
                ($prematch, $match) = $session->waitfor(Match => $switch_main_prompt);
            }
            elsif($hash{ACTION} =~ m/mirror/)
            {
                # Time to turn this port mirror off
                log_msg("Removing ports from the mirror: $hash{MIRROR_NAME}", "CHILD $key");
                $session->print("configure mirror $hash{MIRROR_NAME} delete all");
                ($prematch, $match) = $session->waitfor(Match => $switch_main_prompt);


                my @split = split(',', $hash{MIRRORED_PORTS});
                foreach(@split)
                {
                    chomp;
                    $session->print("configure mirror $hash{MIRROR_NAME} add $_");
                    ($prematch, $match) = $session->waitfor(Match => $switch_main_prompt);
                }
                
                # Call script to log into mirror server and start a capture
                my $command = ROOT . "/embedded_network_mirror.pl";
                $command .= " --mirror_name $hash{MIRROR_NAME}";
                $command .= " --file_name $hash{PCAP_NAME}";
                $command .= " --file_size 10240";
                if($hash{PCAP_DURATION_TYPE} =~ m/packets/)
                {
                    $command .= " --packet_count $hash{PCAP_DURATION}";
                    $command .= " --duration " . MAX_PCAP_DURATION; 
                }
                else
                {
                    $command .= " --duration $hash{PCAP_DURATION}";
                }
                # Must be last item on command
                $command .= " >> $embedded_network_dir/mirror.log 2>&1";

                log_msg("Executing command: $command", "CHILD $key");

                system("$command &");
            }
            elsif($hash{ACTION} =~ m/create-vman/)
            {
                log_msg("Creating vman $hash{VMAN_NAME} with vlan id $hash{VLAN_ID}", "CHILD $key");
                $session->print("create vman $hash{VMAN_NAME} tag $hash{VLAN_ID}");
                ($prematch, $match) = $session->waitfor(Match => $switch_main_prompt);
            }
            elsif($hash{ACTION} =~ m/delete-vman/)
            {
                log_msg("Deleting vman $hash{VMAN_NAME}", "CHILD $key");
                $session->print("delete vman $hash{VMAN_NAME}");
                ($prematch, $match) = $session->waitfor(Match => $switch_main_prompt);
            }
            else
            {
                log_msg("Unknown action: $hash{ACTION}", "CHILD $key ERROR");
                next;
            }

            $do_save = 1;

            # Remove the configuration file as it is now no longer needed
            unlink $hash{FILE_NAME};
        }

        if($do_save)
        {
            $session->print("save configuration");
            ($prematch, $match) = $session->waitfor(Match => '/\(y\/N\)/');
            $session->print("y");
            ($prematch, $match) = $session->waitfor(Match => $switch_main_prompt, Timeout => 30);

            log_msg("Switch has successfully been configured and saved.", "CHILD $key");
        }

        $session->close;

        exit 0;
    }
}

foreach(@child_pids)
{
    my $tmp = waitpid($_, 0);
    $? = $? >> 8;
    if($? != 0)
    {
        log_msg("Child $tmp finished with result $?", "ERROR");
    }
}

exit 0;

END
{
    if(!$child_process)
    {
        if($do_cleanup)
        {
            #log_msg("Removing script.running file from $embedded_network_dir");
            #sleep 10;
            unlink $script_running_file;
        }
        else
        {   
            log_msg("Exiting embedded_network processing without removing script file");
        }
    }
}

