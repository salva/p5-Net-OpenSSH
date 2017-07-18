#!/usr/bin/perl

use strict;
use warnings;

use Net::OpenSSH;
use Expect;

select STDOUT; $| = 1;
select STDERR; $| = 1;

@ARGV == 3 or die <<USAGE;
Usage:
  $0 host old_password new_password
USAGE

my ($host, $old, $new) = @ARGV;

my $timeout = 20;
my $debug = 0;

my $ssh = Net::OpenSSH->new($host, password => $old);

my ($pty, $pid) = $ssh->open2pty("passwd")
    or die "open2pty failed: " . $ssh->error . "\n";

my $expect = Expect->init($pty);
$expect->raw_pty(1);
$debug and $expect->log_user(1);

sub answer_passwd {
    my ($pattern, $pass) = @_;

    $debug and print "waiting for password prompt\n";
    $expect->expect($timeout, -re => $pattern)
        or die "expect failed\n";
    $debug and  print "prompt seen\n";

    $expect->send("$pass\n");
    $debug and print "password sent\n";

    $expect->expect($timeout, "\n")
        or die "bad password\n";
}

answer_passwd('current.*:', $old);
answer_passwd('new.*:', $new);
answer_passwd('new.*:', $new);

$expect->expect($timeout, "success") or die "Failed!\n";

print "password updated\n";
