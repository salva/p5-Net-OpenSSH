#!/usr/bin/perl

use strict;
use warnings;

use Net::OpenSSH;
use Expect;

select STDOUT; $| = 1;
select STDERR; $| = 1;

my $password = $ARGV[0];
my $timeout = 20;

my $debug = 0;

my $ssh = Net::OpenSSH->new('test@127.0.0.1', password => $password);

# my ($pty, $pid) = $ssh->open2pty("sudo cat /etc/shadow")

# After a successful sudo operation, it doesn't request the password
# again until some time after, handling this undeterministic behaviour
# is a pain in the ass, so we just clear any cached credentials
# calling "sudo -k" first as follows:
my ($pty, $pid) = $ssh->open2pty("sudo -k; sudo cat /etc/shadow")
    or die "open2pty failed: " . $ssh->error . "\n";

my $expect = Expect->init($pty);
$expect->raw_pty(1);
$debug and $expect->log_user(1);

$debug and print "waiting for password prompt\n";
$expect->expect($timeout, ':')
    or die "expect failed\n";
$debug and  print "prompt seen\n";

$expect->send("$password\n");
$debug and print "password sent\n";

$expect->expect($timeout, "\n")
    or die "bad password\n";
$debug and print "password ok\n";

while(<$pty>) {
    print "$. $_"
}


