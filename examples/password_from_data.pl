#!/usr/bin/perl

use strict;
use warnings;

use Net::OpenSSH;

@ARGV >= 2 or die "Usage:\n  $0 host cmd [arg1 [arg2 [...]]]\n\n";

my ($host, @cmd) = @ARGV;

my $ssh = Net::OpenSSH->new($host);

$ssh->system({stdin_fh => \*DATA}, sudo => -kSp => '', '--', @cmd);

__DATA__
my-remote-password


