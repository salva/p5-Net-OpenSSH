#!/usr/bin/perl

use strict;
use warnings;

my $ssh_mux = $ENV{SSH_MUX};
print STDERR "SSH_MUX=$ssh_mux\n";
defined $ssh_mux or die "SSH_MUX is not defined\n";
-S $ssh_mux or die "'ssh_mux' is not a socket\n";

do {
    exec ssh => -S => $ssh_mux, @ARGV
};
die "Unable to execute ssh program: $!\n";

