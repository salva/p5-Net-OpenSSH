#!/usr/bin/perl

use strict;
use warnings;

use Net::OpenSSH;
use Net::Telnet;

$Net::OpenSSH::debug = -1;

my $ssh = Net::OpenSSH->new('localhost');
my ($fh, $pid) = $ssh->open2pty();
my $conn = Net::Telnet->new(Fhopen => $fh);
my @lines = $conn->cmd("find /tmp");
print @lines;
my @lines1 = $conn->cmd("ls");
print "\n\nls:\n", @lines1;
