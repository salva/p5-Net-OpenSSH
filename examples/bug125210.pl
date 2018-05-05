#!/usr/bin/perl
use strict;
use warnings;
use Net::OpenSSH;
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use Test::More tests => 2;

# warn $$;
# sleep 5;

my $host = "localhost";
my $ssh = Net::OpenSSH->new($host);
$ssh->error and die $ssh->error;

my($rout, $pid) = $ssh->pipe_out("echo", "bla");

sleep 2;

close $rout;

{
    my $flags = fcntl(STDOUT, F_GETFL, 0) or die $!;
    is(($flags & O_NONBLOCK), 0, "no O_NONBLOCK on STDOUT")
}
{
    my $flags = fcntl(STDERR, F_GETFL, 0) or die $!;
    is(($flags & O_NONBLOCK), 0, "no O_NONBLOCK on STDERR")
}

__END__
