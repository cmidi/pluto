#!/usr/bin/perl -w

use strict;
use warnings;
use Acme::embtestlib;
use Errno;
use autodie qw(:default);
use feature "switch";
use Getopt::Long;
use DBI;

use constant MAX_EXISITING_USER_PCAPS => 10;
use constant TELNET_TIMEOUT           => 30;

my $embtest_root_dir           = ROOT;
my $embedded_network_dir       = $embtest_root_dir . "/embedded_network";
my $embedded_network_pcaps_dir = $embedded_network_dir . "/pcaps";
my $db_host                    = DB_HOST;
my $db_user                    = DB_USER;
my $db_pass                    = DB_PASS;
my $database                   = DB_DATABASE;
my $db_entry;
my $q                          = "";
my $debug                      = 0;
my $mirror_name                = "mirror-4094";
my $host                       = "";
my $interface                  = "";
my $duration                   = "30";
my $packet_count               = 0;
my $file_name                  = "smcculley_111111.pcap";
my $file_size                  = 1024;
my $scp_server                 = "172.30.0.97";
my $scp_user                   = "acme";
my $scp_password               = "abc123";
my $scp_loc                    = "/home/acme";
my $prematch                   = "";
my $match                      = "";
my @existing_files             = ();
my $file_match                 = "";
my $reserve_time;

GetOptions("mirror_name=s"  => \$mirror_name,
           "duration=i"     => \$duration,
           "packet_count=i" => \$packet_count,
           "interface=s"    => \$interface,
           "file_name=s"    => \$file_name,
           "file_size=i"    => \$file_size,
           "scp_server=s"   => \$scp_server,
           "scp_user=s"     => \$scp_user,
           "scp_password=s" => \$scp_password,
           "scp_location=s" => \$scp_loc); 

# Get beginning match (going to be username) of the file handle to be used when cleaning up older pcaps
# from the pcaps directory
my @split = split(/_/, $file_name);
if(@split > 1)
{
    $file_match = $split[0]; 
}

#Connect to DB 
#log_msg("Host: $db_host, User: $db_user, Pass: $db_pass, Database: $database");
#log_msg("");
my $db_handle = DBI->connect("DBI:mysql:$database:$db_host", $db_user, $db_pass,{ RaiseError => 1,  })
                or die "connect: cannot connect to database: $DBI::errstr";

my $current_time = time();

$q  = "SELECT server_ip, server_interface, reserve_time FROM embedded_network_mirrors AS t1";
$q .= " WHERE t1.mirror_name = '$mirror_name'";
$q .= " LIMIT 1";
$db_entry = $db_handle->prepare($q);
$db_entry->execute;

while(my $hash_ref = $db_entry->fetchrow_hashref)
{
    $host = $hash_ref->{server_ip};
    $interface = $hash_ref->{server_interface};
    $reserve_time = $hash_ref->{reserve_time};
    last;
}

if($host eq "" or $interface eq "")
{
    log_msg("Invalid host: $host or interface: $interface", "ERROR");
    exit 1;
}

my $session = Net::Telnet->new(Host => $host);
if(!defined($session) )
{
    log_msg("Can't connect HOST $host: $!");
    exit 1;
}

$session->input_log(*STDOUT);
$session->login(Name => "embtest", Password => "abc123", Timeout => TELNET_TIMEOUT);

$q = "UPDATE embedded_network_mirrors AS t1";
$q .= " SET t1.start_time = '$current_time'";
$q .= ", t1.duration_seconds = '$duration'";
if(!defined($reserve_time))
{
    log_msg("Reserve time must have been accidentally wiped, lets update it");
    $q .= ", t1.reserve_time = '$current_time'";
}
$q .= " WHERE t1.mirror_name = '$mirror_name'";
$q .= " LIMIT 1";

# log_msg("Query: $q", "CHILD $key");
$db_entry = $db_handle->prepare($q);
$db_entry->execute;

my $command = "dumpcap -i $interface -a duration:$duration -a filesize:$file_size -w $file_name";

if($packet_count)
{
    $command .= " -c $packet_count";
}

my @results = $session->cmd(String => "$command",
                            Timeout => ($duration + 10),
                            Prompt => '/\(\d+\.\d+%\)/');


$q = "UPDATE embedded_network_mirrors AS t1";
$q .= " SET t1.duration_seconds = '1'";
$q .= " WHERE t1.mirror_name = '$mirror_name'";
$q .= " LIMIT 1";

# log_msg("Query: $q", "CHILD $key");
$db_entry = $db_handle->prepare($q);
$db_entry->execute;

# Iterate over embedded_network directory pulling out all valid .config files
opendir(my $dh, $embedded_network_pcaps_dir) or die $!;
my @files = grep {/^$file_match/} readdir($dh);
@files = sort {-M "$embedded_network_pcaps_dir/$b" <=> -M "$embedded_network_pcaps_dir/$a"} @files;
while(my $file = shift @files)
{
    if($file =~ m/^$file_match/)
    {
        push(@existing_files, $embedded_network_pcaps_dir . "/" . $file);
    }
    else
    {
        # Don't care about anything else
        next;
    }
}

closedir($dh);

if(@existing_files >= MAX_EXISITING_USER_PCAPS)
{
    for(my $i = 0; $i < (@existing_files - (MAX_EXISITING_USER_PCAPS - 1)); $i++)
    {
        # Remove oldest pcaps
        unlink($existing_files[$i]);
    }
}

# SCP pcap over to embtest server
$session->print("scp $file_name " . EMBTEST_USER . '@' . EMBTEST_HOST . ":$embedded_network_pcaps_dir/$file_name");
($prematch, $match) = $session->waitfor(Match => '/\(yes\/no\)|Password:/', Timeout => TELNET_TIMEOUT);
if($match =~ /\(yes\/no\)/)
{
    $session->print("yes");
    ($prematch, $match) = $session->waitfor(Match => '/Password:/');
}
$session->print(EMBTEST_PASS);
($prematch, $match) = $session->waitfor(Match => '/\]\$/');

chmod 0755, "$embedded_network_pcaps_dir/$file_name";

$session->close;
