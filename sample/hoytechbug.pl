#!/usr/bin/perl

use strict;
use warnings;

use Net::OpenSSH;

my $ssh = Net::OpenSSH->new('localhost');
$ssh->die_on_error;

my @pid;
for (0..10) {
    push @pid, $ssh->spawn({tty => 1}, 'id >/dev/null');
    $ssh->die_on_error;
}

waitpid $_, 0 for grep defined, @pid;
print "ok!\r\n";
sleep 1;

