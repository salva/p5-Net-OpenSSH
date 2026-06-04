#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Net::OpenSSH;

my $sizeof_sun_path = ($^O eq 'linux' ? 108 :
                       $^O =~ /bsd/i  ? 104 :
                       $^O eq 'hpux'  ? 92  : undef);

plan skip_all => "sun_path size is not known on $^O"
    unless defined $sizeof_sun_path;

plan tests => 3;

sub ctl_path_of_length {
    my $length = shift;
    my $prefix = '/tmp/';
    die "test prefix is too long" if length($prefix) >= $length;
    return $prefix . ('x' x ($length - length($prefix)));
}

my $good = ctl_path_of_length($sizeof_sun_path - 1);
my $bad = ctl_path_of_length($sizeof_sun_path);

my $ssh = Net::OpenSSH->new(host => 'localhost', ctl_path => $good,
                            connect => 0, strict_mode => 0);
is($ssh->error + 0, 0, 'usable maximum ctl_path length is accepted');
is(length($ssh->get_ctl_path), $sizeof_sun_path - 1, 'accepted ctl_path has expected length');

$ssh = Net::OpenSSH->new(host => 'localhost', ctl_path => $bad,
                         connect => 0, strict_mode => 0);
like($ssh->error, qr/max permissible size for \Q$^O\E is @{[$sizeof_sun_path - 1]}/,
     'ctl_path requiring an extra NUL byte is rejected');
