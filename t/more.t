#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 1;

use Net::OpenSSH::More;

ok(Net::OpenSSH->can('scp_cat'), 'Net::OpenSSH::More installs scp_cat');
