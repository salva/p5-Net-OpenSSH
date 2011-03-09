#!/usr/bin/perl

# see http://perlmonks.org/?node_id=890441

use strict;
use warnings;

use Net::OpenSSH;
use Expect;

@ARGV == 3 or die <<EOU;
Usage:
  $0 host user_passwd root_passwd

EOU

my $host = $ARGV[0];
my $pass1 = $ARGV[1];
my $pass2 = $ARGV[2];

my $ssh = Net::OpenSSH->new($host, passwd => $pass1);
$ssh->error and die "unable to connect to remote host: " . $ssh->error;

$ssh->system("sudo -K");

my ( $pty, $pid ) = $ssh->open2pty({stderr_to_stdout => 1}, 'sudo', -p => 'configtest:', 'bash', '-i')
    or return "failed to attempt sudo bash: $!\n";

my $expect = Expect->init($pty);

$expect->expect(2,
                [ qr/configtest:/ => sub { shift->send("$pass2\n"); exp_continue;} ],
                [ qr/Sorry/       => sub { die "Login failed" } ],
                [ qr/.*#\s+/      => sub { print shift->match }]
               ) or die "Timeout!";

$expect->interact();

