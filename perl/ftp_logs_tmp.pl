#!/usr/bin/perl -w

#FTP logs from SD

use Acme::embtestlib;
use strict;
use Getopt::Long;
use Errno;
use autodie qw(:default);
use warnings;
use Net::SFTP::Foreign;

my $USER      = "user";
my $PASS      = "acme";

my $logging   = 0;
my $rm_logs   = 0;
my $dest_dir  = ".";
my $host;
my $FH;
my $isLinux;
my $date      = get_timestamp();
my $tag       = "FTPL";



#Define varying directory structures.
my %linux = ( opt_crash  => '/opt/crash',
              logs       => '/opt/logs',
              code_crash => '/code/crash' );


my %vx    = ( code_crash => '/code/crash',
              logs       => '/ramdrv/logs' );


GetOptions( "host=s"     => \$host,
            "logging=i"  => \$logging,
            "dest=s"     => \$dest_dir,
            "rm-logs=s" => \$rm_logs);

unless($host)
{
    print("\n");
    print("FTP LOGS USAGE\n");
    print("-host (ftp host)\n");
    print("-logging (send ls portion to a log file, dir.log)\n");
    print("-dest    (destination dir)\n");
    print("-rm-logs (1 to rm logs and exit\n");
    print("\n");
}

#Set up SFTP session.
my $sftp = Net::SFTP::Foreign->new(host=> $host, user=> $USER, password=> $PASS, autodie=> 0);

my $dir_ls = $sftp->ls();

log_msg("Starting script which gathers logs via sftp..\n", "$tag");

#Determine linux / vxworks
foreach my $ls_line (@$dir_ls)
{   
    #Currently determine if linux by checking for /opt - This should be improved.
    if($ls_line->{longname} =~ "/opt")
    {
        $isLinux = 1;
    }

    #This guy builds his own(bad) version of ls -l, split 6 to get columns and date.
#    my @ll = split('\s+', $ls_line->{longname}, 6);
#    printf( "%-10s %2d %-4s %-3s %12d %-12s\n", $ll[0], $ll[1], $ll[2], $ll[3], $ll[4], $ll[5]);
}

#Set pointer to which hash to use.
my $os_dirs_href = (($isLinux) ? \%linux : \%vx);

if($rm_logs)
{
    #Remove specific logs, called from cleansd.exp only.
    #Sigh. recursive rm removes directory as well. Loop mode activated.

    log_msg("Begin cleanup of directories.", "$tag");
    foreach my $key (keys %$os_dirs_href)
    {
        my $count  = 0;
        my $ls_lrt = $sftp->ls("$os_dirs_href->{$key}/");
        &ls_lrt($ls_lrt);
        
        if(!@$ls_lrt) { next; }
        
        foreach my $ls_line (@$ls_lrt)
        {
            #Skip specific things here. Gonna leave core files.
            #NOTE: Whatever we don't delete needs to be skipped at the "get" part.
            #cont- we can make an array of stuff to skip if it gets excessive.
            if($ls_line->{filename} =~ "core") { next; }
            
            $sftp->remove("$os_dirs_href->{$key}/$ls_line->{filename}");
            $count++;
        }
        log_msg("Removed $count files from $os_dirs_href->{$key}.", "$tag");
    }
    log_msg("Finished cleaning directories. Exiting..", "$tag");
    exit 0;
}

sub ls_lrt
{
    my $array_ref = shift;

    #Array ref of hash refs including ref to SFTP attribute object containing mtime. Party. Because SFTPguy sending "ls -lrt" is too much work.    
    @$array_ref = sort {$a->{a}->{mtime} <=> $b->{a}->{mtime}} @$array_ref;

}
