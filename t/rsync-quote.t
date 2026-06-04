#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 5;
use Net::OpenSSH;

is(Net::OpenSSH->_rsync_quote('ssh'), q{'ssh'}, 'plain arguments are quoted');
is(Net::OpenSSH->_rsync_quote('a b'), q{'a b'}, 'space-containing arguments are quoted');
is(Net::OpenSSH->_rsync_quote(q{a'b}), q{'a'\''b'}, 'single quotes are escaped');
is(Net::OpenSSH->_rsync_quote('a%b%c'), q{'a%%b%%c'}, 'all percent characters are doubled');

my @quoted = Net::OpenSSH->_rsync_quote('ssh', '-S', '/tmp/a b');
is_deeply(\@quoted, [q{'ssh'}, q{'-S'}, q{'/tmp/a b'}], 'list context returns quoted arguments');
