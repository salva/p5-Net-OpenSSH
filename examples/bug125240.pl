#!/usr/bin/perl

use strict;
use warnings;
use 5.010;

use Net::OpenSSH;

my @sshs;

for my $i (0..100) {
    my $ssh = Net::OpenSSH->new('localhost', master_pty_force => 1);
    push @sshs, $ssh;
    my ($fh) = $ssh->pipe_in('uname -a');
    warn "i: $i, fd: ".fileno($fh)."\n";
    close $fh;
    $ssh->disconnect
}
