#!/usr/bin/perl

use strict;
use warnings;
use Cwd;

use Net::OpenSSH;
use Test::More;

sub test_uri {
    my ($args, $expected, $comment) = @_;
    $args = [$args] unless ref $args;
    $comment = join(', ', $args->[0], map "$args->[$_*2-1] => $args->[$_*2]", 1 .. ($#$args/2))
        unless defined $comment;
    my $out = Net::OpenSSH->parse_connection_opts({host => @$args});
    if ($out) {
        if ($expected) {
            for my $k (keys %$out) {
                my $v = $out->{$k};
                defined $v or next;
                my $ev = $expected->{$k};
                unless (defined $ev and $ev eq $v) {
                    next if not defined $ev and $k eq 'host_squared';
                    fail $comment;
                    my $qev = (defined $ev ? "'$ev'" : '(undef)');
                    diag "bad value for '$k'\ngot: '$v'\nexpected: $qev\n";
                    return;
                }
            }
            for my $k (keys %$expected) {
                my $ev = $expected->{$k};
                defined $ev or next;
                unless (defined $out->{$k}) {
                    fail $comment;
                    my $qev = (defined $ev ? "'$ev'" : '(undef)');
                    diag "bad value for '$k'\ngot: (undef)\nexpected: $qev\n";
                    return;
                }
            }
        }
        else {
            fail $comment;
            diag "uri parsing did not fail as expected";
            return;
        }
    }
    else {
        if ($expected) {
            fail $comment;
            diag "uri parsing failed";
            return;
        }
    }
    ok($comment);
}

test_uri('foo@bar', { host => 'bar', user => 'foo' });
test_uri('foo@bar.com', { host => 'bar.com', user => 'foo' });
test_uri('bar', { host => 'bar' });
test_uri('foo:bar@doz', { host => 'doz', user => 'foo', password => 'bar' });
test_uri('foo@bar@doz', { host => 'doz', user => 'foo@bar' });
test_uri('foo:metapun@doz', { host => 'doz', user => 'foo', password => 'metapun' });
test_uri('foo:meta@pun@doz', { host => 'doz', user => 'foo', password => 'meta@pun' });
test_uri('foo:meta:pun@doz', { host => 'doz', user => 'foo', password => 'meta:pun' });
test_uri('foo:meta:p@un@doz', { host => 'doz', user => 'foo', password => 'meta:p@un' });
test_uri('foo:met@a:pun@doz', { host => 'doz', user => 'foo', password => 'met@a:pun' });
test_uri('foo:met@a:p@un@doz', { host => 'doz', user => 'foo', password => 'met@a:p@un' });
test_uri('foo:metapun@doz', { host => 'doz', user => 'foo', password => 'metapun' });
test_uri('foo@bar:meta@pun@doz', { host => 'doz', user => 'foo@bar', password => 'meta@pun' });
test_uri('foo@bar:meta:pun@doz', { host => 'doz', user => 'foo@bar', password => 'meta:pun' });
test_uri('foo@bar:meta:p@un@doz', { host => 'doz', user => 'foo@bar', password => 'meta:p@un' });
test_uri('foo@bar:met@a:pun@doz', { host => 'doz', user => 'foo@bar', password => 'met@a:pun' });
test_uri('foo@bar:met@a:p@un@doz', { host => 'doz', user => 'foo@bar', password => 'met@a:p@un' });
test_uri('username@SAMBA.MYDOMAIN.COM@myhost.mydomain.com',
         { host => 'myhost.mydomain.com', user => 'username@SAMBA.MYDOMAIN.COM' }, '#RT105253');
test_uri('foo@[fe80::1:f6ff:fe01:47%eth0]',
         { host => 'fe80::1:f6ff:fe01:47%eth0', user => 'foo', ipv6 => 1 }, 'IPv6 with zone index');

done_testing();
