#!/usr/bin/perl

use strict;
use warnings;

use Net::OpenSSH;
use Getopt::Long;

my @envs;

my $usage = "Usage:\n  $0 --env=FOO --env=BAR [user\@]host command args\n\n";

GetOptions("env=s" => \@envs)
    or die $usage;

my $host = shift @ARGV;
die $usage unless defined $host and @ARGV;

my $ssh = Net::OpenSSH->new($host);
$ssh->error and die "Unable to connect to remote host: " . $ssh->error;

my @cmds;
for my $env (@envs) {
    next unless defined $ENV{$env};
    push @cmds, "export " . $ssh->shell_quote($env) .'='.$ssh->shell_quote($ENV{$env})
}

my $cmd = join('&&', @cmds, '('. join(' ', @ARGV) .')');
warn "remote command: $cmd\n";
$ssh->system($cmd);

