#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 7;
use Net::OpenSSH::Constants qw(OSSH_MASTER_FAILED);
use Net::OpenSSH::ConnectionCache;

{
    package Test::Net::OpenSSH::ConnectionCache::SSH;

    sub new {
        my $class = shift;
        return bless { @_ }, $class;
    }

    sub error { shift->{error} || 0 }
    sub wait_for_master { 1 }
}

local $Net::OpenSSH::ConnectionCache::MAX_SIZE = 2;
local %Net::OpenSSH::ConnectionCache::cache = (
    live   => Test::Net::OpenSSH::ConnectionCache::SSH->new(error => 0),
    failed => Test::Net::OpenSSH::ConnectionCache::SSH->new(error => OSSH_MASTER_FAILED),
    empty  => undef,
);

my $ssh;
eval {
    $ssh = Net::OpenSSH::ConnectionCache::_factory(
        'Test::Net::OpenSSH::ConnectionCache::SSH',
        host => 'cache-test-host'
    );
};

is($@, '', 'cache cleanup does not die on empty entries');
ok($ssh, 'factory returns a new object');
ok(!exists $Net::OpenSSH::ConnectionCache::cache{failed}, 'failed master entry is removed');
ok(!exists $Net::OpenSSH::ConnectionCache::cache{empty}, 'empty cache entry is removed');
ok(exists $Net::OpenSSH::ConnectionCache::cache{live}, 'live cache entry is retained');
ok((keys %Net::OpenSSH::ConnectionCache::cache) <= $Net::OpenSSH::ConnectionCache::MAX_SIZE,
   'cache is reduced below the configured maximum');

Net::OpenSSH::ConnectionCache::clean_cache();
is(scalar keys %Net::OpenSSH::ConnectionCache::cache, 0, 'clean_cache clears cache');
