#!/usr/bin/perl

use Getopt::Long;

my $user = "backup";
my $userPassword = "abc123";
my $database = "embtestdb";
my $backupDirectory = "/home/embtest/backups/mysql/";

sub get_timestamp()
{
    (my $sec, my $min, my $hour, my $mday, my $mon, my $year, my $wday, my $yday, my $isdst) = localtime(time);

    if ($mon < 10) { $mon = "0$mon"; }
    if ($hour < 10) { $hour = "0$hour"; }
    if ($min < 10) { $min = "0$min"; }
    if ($sec < 10) { $sec = "0$sec"; }
    $year=$year+1900;

    return $mon . '/' . $mday . '/' . $year . " " . $hour . ':' . $min . ':' . $sec;
}

sub log_msg(@)
{
    my $message = $_[0];
    my $prefix = $_[1];

    unless($prefix)
    {
        $prefix = "INFO";
    }

    print get_timestamp() . " ${prefix}: $message\n";
}

GetOptions("user=s"      => \$user,
           "password=s"  => \$userPassword,
           "database=s"  => \$database,
           "directory=s" => \$backupDirectory);

log_msg("Entered mysql-backup.pl");
log_msg("User = ${user}, User Password = ${userPassword}, Database = ${database}");

if(!($backupDirectory =~ /\/$/))
{
	$backupDirectory .= "/";
}

log_msg("Backup Directory = ${backupDirectory}");

my $mytime = time();

log_msg("Time since epoch = ${mytime}");

my $command = "mysqldump --add-drop-table --user=${user} --password=${userPassword} ${database} > ${backupDirectory}${database}_${mytime}.sql";
log_msg("Executing ${command}");
my @results = `${command}`;
log_msg("Results:\n@{results}");

log_msg("Changing working directory to: ${backupDirectory}");
chdir($backupDirectory);

$command = "tar -zvcf ${database}_${mytime}.tar.gz ${database}_${mytime}.sql";
log_msg("Executing ${command}");
my @results = `${command}`;
log_msg("Results:\n@{results}");

$command = "rm ${database}_${mytime}.sql";
log_msg("Executing ${command}");
my @results = `${command}`;
log_msg("Results:\n@{results}");

log_msg("Exiting mysql-backup.pl");

exit 0;
