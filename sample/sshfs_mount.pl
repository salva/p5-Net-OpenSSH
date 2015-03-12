#!/usr/bin/perl

use strict;
use warnings;
use 5.010;

use Net::OpenSSH 0.65;

@ARGV == 3 or die <<USAGE;
Usage:
  $0 host remote_directory mount_point
USAGE

my $uri = shift;
my $remote = shift;
my $local = shift;

my $ssh = Net::OpenSSH->new($uri);
$ssh->die_on_error;

my $dev = (stat $local)[0] // die "$local: $!";

my $sshfs_pid = $ssh->sshfs_import($remote, $local)
    or $ssh->die_on_error;

$| = 1;
for (1..20) {
    my $new_dev = (stat $local)[0];
    if ($new_dev != $dev) {
        my $master_pid = $ssh->disown_master;
        $ssh->stop;
        print "\nremote $remote mounted in $local, sshfs PID: $sshfs_pid, master ssh PID: $master_pid\n";
        exit(0);
    }
    print '.';
    sleep 1;
}

print "Time out!\n";
kill TERM => $sshfs_pid;



