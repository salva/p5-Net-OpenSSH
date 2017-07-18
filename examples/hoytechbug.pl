#!/usr/bin/perl

use strict;
use warnings;

use Net::OpenSSH;

my $host = shift // 'localhost';

for my $count (0..1e6) {
    my $ssh = Net::OpenSSH->new($host);
    next if $ssh->error;

    for my $mid (0..5) {
        my @pid;
        for (0..5) {
            push @pid, $ssh->spawn({tty => 1}, 'id >/dev/null');
            $ssh->die_on_error;
        }
        waitpid $_, 0 for grep defined, @pid;
        print "[$count/$mid] ok!\r\n";
    }
}


