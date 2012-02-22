#!/usr/bin/perl

use strict;
use warnings;

# This script monitorizes a directory using inotify and when some
# change is detected, uses rsync to update a remote copy.
#
# See: http://stackoverflow.com/q/6781104/124951


use Net::OpenSSH;
use Linux::Inotify2;
use Time::HiRes qw(sleep);

my $usage = "Usage:\n  $0 local_dir [user\@]host remote_dir\n\n";

@ARGV == 3 or die $usage;
my ($local, $host, $remote) = @ARGV;

-d $local or die $usage;

my $ssh = Net::OpenSSH->new($host);
$ssh->error and die "unable to connect to remote host: " . $ssh->error;

my $inotify = Linux::Inotify2->new;
$inotify->watch ($local, IN_MODIFY|IN_MOVED_TO);

$ssh->rsync_put({verbose => 1, glob => 1}, "$local/*", $remote);

while (1) {
    my @events = $inotify->read or die "read error: $!";
    my %changed;
    $changed{"$local/$_->{name}"} = 1 for @events;
    $ssh->rsync_put({verbose => 1}, keys %changed, $remote);
    sleep 0.1;
}
