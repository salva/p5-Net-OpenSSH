#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 7;

use Net::OpenSSH::ShellQuoter::MSCmd;

my $q = Net::OpenSSH::ShellQuoter::MSCmd->new;

is($q->quote('abc'), 'abc', 'plain arguments are unchanged');
is($q->quote('a b'), '"a b"', 'space-containing arguments are grouped');
is($q->quote("a\tb"), "\"a\tb\"", 'tab-containing arguments are grouped');
is($q->quote(''), '""', 'empty arguments are preserved');
is($q->quote('a&b'), 'a^&b', 'cmd metacharacters are escaped');
is($q->quote('a & b'), '"a ^& b"', 'grouping is applied after escaping metacharacters');

eval { $q->quote("a\n") };
like($@, qr/can't quote newlines/, 'newlines are rejected');
