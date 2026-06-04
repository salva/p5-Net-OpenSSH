#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 5;

use Net::OpenSSH::ModuleLoader;

ok(_load_module('strict'), 'loads a valid module name');

eval { _load_module('strict; die "boom"') };
like($@, qr/bad Perl module name/, 'rejects unsafe module names');

eval { _load_module('strict', 999_999) };
like($@, qr/strict version 999999 required|strict version 999999 required--this is only version/,
     'uses standard VERSION checks for too-new requirements');

{
    package Test::Net::OpenSSH::ModuleLoader::Versioned;
    our $VERSION = '1.02';
}

$INC{'Test/Net/OpenSSH/ModuleLoader/Versioned.pm'} = __FILE__;

ok(_load_module('Test::Net::OpenSSH::ModuleLoader::Versioned', '1.01'),
   'accepts a sufficient version');

eval { _load_module('Test::Net::OpenSSH::ModuleLoader::Versioned', '1.03') };
like($@, qr/Test::Net::OpenSSH::ModuleLoader::Versioned version 1.03 required/,
     'rejects an insufficient version');
