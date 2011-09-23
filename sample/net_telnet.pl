#!/usr/bin/perl

use strict;
use warnings;

use Net::OpenSSH;
use Net::Telnet;
use Data::Dumper;
use Errno ();

@ARGV == 1 or die "Usage:\n  $0 host\n\n";
my $ssh = Net::OpenSSH->new(@ARGV);

my ($pty, $pid) = $ssh->open2pty({stderr_to_stdout => 1})
    or die "unable to start remote shell: " . $ssh->error;
my $telnet = Net::Telnet->new( -fhopen => $pty,
                               -prompt => '/.*\$ $/',
                               -telnetmode => 0,
                               -cmd_remove_mode => 1,
                               -output_record_separator => "\r" );

$telnet->waitfor(-match => $telnet->prompt,
                 -errmode => "return")
    or die "login failed: " . $telnet->lastline;

my @who = $telnet->cmd("who");
my @ls  = $telnet->cmd("ls");

print Dumper [\@who, \@ls];

$telnet->close;
while (1) {
    my $rc = waitpid($pid, 0);
    last if ($rc == $pid or $rc == Errno::ECHILD());
    sleep 1;
}
