#!/usr/bin/perl -w

#FTP logs from SD

#Mode 2 - Get configs from SD (does not get logs when getting config)

use Acme::embtestlib;
use strict;
use Getopt::Long;
use Errno;
use autodie qw(:default);
use warnings;
use Net::SFTP::Foreign;

###################################################################################

#Untaint every input argument(ARGV) and every environmental variable (ENV).
#It is not secure, but we have to do it for now becasue anvil is run with setuid bit

&untaint_ARGV_ENV();

###################################################################################

my $USER      = "user";
my $PASS      = "acme";

my $logging   = 0;
my $rm_logs   = 0;
my $dest_dir  = ".";
my $host;
my $FH;
my $date      = get_timestamp();
my $tag       = "FTPL";

#For "get config" functionality.
my $save_config = "";

#Debug
my $nick        = 0;


#Define varying directory structures.
my %linux = ( opt_crash  => '/opt/crash',
              logs       => '/opt/logs',
              code_crash => '/code/crash' );


my %vx    = ( code_crash => '/code/crash',
              logs       => '/ramdrv/logs' );


GetOptions( "host=s"        => \$host,
            "logging=i"     => \$logging,
            "dest=s"        => \$dest_dir,
            "rm-logs=s"     => \$rm_logs,
            "save-config=s" => \$save_config,
            "nick=i"        => \$nick );


unless($host)
{
    print("\n");
    print("FTP LOGS USAGE\n");
    print("-host (ftp host)\n");
    print("-logging (send ls portion to a log file, dir.log)\n");
    print("-dest    (destination dir)\n");
    print("-rm-logs (1 to rm logs and exit\n");
    print("-save-config (Path and Name of config: ex /home/somewhere/derp/myConfig.gz\n");
    print("             ( Note: Standalone feature, doesn't get or remove logs while saving config.\n");
    print("\n");
    exit 0;
}

my $tmpstr = ($rm_logs) ? "removes" : "gathers";
log_msg("Starting script which $tmpstr logs from $host via sftp..\n", "$tag");

#Set up SFTP session. Manual retry logic since the module has no retry param..
#Dumb: Bare block here, "do" isn't considered a loop, but bare block is a loop.
#Without bareblock, "last" errors out the script.
my $sftp;
my $error_count = 0;
{
    do {

        $sftp = Net::SFTP::Foreign->new(host=> $host, user=> $USER, password=> $PASS, autodie=> 0);
        
        if(!$sftp->error) 
        {
            last;
        }
        
        if($error_count >= 30)
        {
            log_msg("Reached maximum retry count. Giving up.", "$tag");
            exit 0;
        }
        
        $error_count++;
        log_msg("Could not connect to host ($host) - retrying in 10s - $error_count/30", "$tag");

        sleep 10;

    } while ($sftp->error);
}

#my $dir_ls = $sftp->ls();

#Determine linux / vxworks
#foreach my $ls_line (@$dir_ls)
#{   
    #Currently determine if linux by checking for /opt - This should be improved.
#    if($ls_line->{longname} =~ "/opt")
#    {
#        log_msg("Using Linux OS dir structure", "$tag");
#        $isLinux = 1;
#    }

#    if($nick)
#    {
#        my $stat_opt = $sftp->stat("/opt");

#        $isLinux = (($stat_opt) ? 1 : 0);

#        log_msg("is linux = $isLinux");
#        if(!$stat_opt)
#        {
#            log_msg("no opt found");
#        }

        #This guy builds his own(bad) version of ls -l, split 6 to get columns and date.
#        my @ll = split('\s+', $ls_line->{longname}, 6);
#        printf( "%-10s %2d %-4s %-3s %12d %-12s\n", $ll[0], $ll[1], $ll[2], $ll[3], $ll[4], $ll[5]);
#    }
#}


my $stat_opt = $sftp->stat("/opt");
my $isLinux = (($stat_opt) ? 1 : 0);
my $version = ($isLinux) ? "linux" : "vxworks";
my $bkup_dir = "/code/gzConfig/";

#Grab config from /code/gzConfig/dataDoc.gz and store it to destination as $save_config
if ($save_config)
{
    if(!$dest_dir)
    {
        log_msg("Saving config requires a destination.", "$tag");
        exit 0;
    }

    if($save_config !~ /\.gz$/ )
    {
        $save_config = $save_config . "\.gz";
    }

    log_msg("Copying config from $bkup_dir to $dest_dir/$save_config", "$tag");
    $sftp->get("$bkup_dir/dataDoc.gz", "$dest_dir/$save_config"); 

    log_msg("Finished copying config, exiting script.", "$tag");
    exit 0;
}

log_msg("Using $version OS dir structure", "$tag");


#Set pointer to which hash to use.
my $os_dirs_href = (($isLinux) ? \%linux : \%vx);

if($nick)
{
    foreach my $key (keys %$os_dirs_href)
    {
        print("key = $key\n");
    }
    exit;
}

if($rm_logs)
{
    #Remove specific logs, called from cleansd.exp only.
    #Sigh. recursive rm removes directory as well. Loop mode activated.

    log_msg("Begin cleanup of directories.", "$tag");
    foreach my $key (keys %$os_dirs_href)
    {
        my $count  = 0;
        my $ls_lrt = $sftp->ls("$os_dirs_href->{$key}/");
        if(!$ls_lrt) { next; }

        &ls_lrt($ls_lrt);
        if(!@$ls_lrt) { next; }
        
        foreach my $ls_line (@$ls_lrt)
        {
            #Currently remove core files too. May want to change this.
#            if($ls_line->{filename} =~ "core") { next; }

            if($ls_line->{filename} =~ /\Qlost+found\E/)
            {
                $sftp->rremove("$os_dirs_href->{$key}/$ls_line->{filename}");
            }
            else
            {
                $sftp->remove("$os_dirs_href->{$key}/$ls_line->{filename}");
            }

            $count++;
        }
        log_msg("Removed $count files from $os_dirs_href->{$key}.", "$tag");
    }
    log_msg("Finished cleaning directories. Exiting..", "$tag");
    exit 0;
}

#Save ls -lrt of crash dirs
for my $key ( keys %$os_dirs_href )
{
    if($key =~ "logs") { next; }

    #Set FH to send ls to log or screen. Default to screen.
    if($logging) 
    {
        open($FH, ">", "$dest_dir/_$key.log");
    }
    else
    {
        $FH = *STDOUT;
    }

    #Grab ls -lrt of crash dir for processing.
    my $ls_lrt = $sftp->ls("$os_dirs_href->{$key}/");
    &ls_lrt($ls_lrt);

    if(!@$ls_lrt)
    {
        print($FH "$date" . " FTPL: $os_dirs_href->{$key} has nothing to display.\n");
        next;
    }

    print($FH "$date" . " PROCESSING: $os_dirs_href->{$key}\n");
    print($FH "-------------------------------------------------------------------------------------\n");
    #Loop through each line of the returned listing and format properly.
    foreach my $ls_line (@$ls_lrt)
    {
        chomp($ls_line->{longname});

        $ls_line->{longname} =~ s/\Q $ls_line->{filename}\E//g;

        #This guy builds his own(bad) version of ls -l, split 6 to get columns and date.
        my @ll = split('\s+', $ls_line->{longname}, 6);

        #Print the columns cleanly. Note 2d, -4s are specific to "acme" and "src" for sbc usage.
        printf($FH "%-10s %2d %-4s %-3s %12d %-12s %-s\n", $ll[0], $ll[1], $ll[2], $ll[3], $ll[4], $ll[5], $ls_line->{filename});
    }
    print($FH "-------------------------------------------------------------------------------------\n");


}

#Separate loop for getting the files.
for my $key ( keys %$os_dirs_href )
{
    #Grab ls -lrt of crash dir for processing.
    my $ls_lrt = $sftp->ls("$os_dirs_href->{$key}/");
    &ls_lrt($ls_lrt);

    if(!@$ls_lrt)
    {
        log_msg("$os_dirs_href->{$key} has no files to get.", "$tag");
        next;
    }
    
    foreach my $ls_line (@$ls_lrt)
    {   
        chomp($ls_line->{longname});

        $ls_line->{longname} =~ s/\Q $ls_line->{filename}\E//g;

        #This guy builds his own(bad) version of ls -l, split 6 to get columns and date.
        my @ll = split('\s+', $ls_line->{longname}, 6);
        

        if(($ls_line->{filename} =~ /core/i) || ($ls_line->{filename} =~ /\Qlost+found\E/))
        {
            printf("$date: Skipping file: %-10s %2d %-4s %-3s %12d %-12s %-s\n", $ll[0], $ll[1], $ll[2], $ll[3], $ll[4], $ll[5], $ls_line->{filename});
            next;
        }
        else
        {
            printf("$date: Getting file:  %-10s %2d %-4s %-3s %12d %-12s %-s\n", $ll[0], $ll[1], $ll[2], $ll[3], $ll[4], $ll[5], $ls_line->{filename});
            $sftp->get("$os_dirs_href->{$key}/$ls_line->{filename}", "$dest_dir/$ls_line->{filename}"); 
        }
    }
}

log_msg("Finished processing, exiting.\n", "$tag");

exit 0;

sub ls_lrt
{
    my $array_ref = shift;

    #Array ref of hash refs including ref to SFTP attribute object containing mtime. Party. Because SFTPguy sending "ls -lrt" is too much work.    
    @$array_ref = sort {$a->{a}->{mtime} <=> $b->{a}->{mtime}} @$array_ref;

}
