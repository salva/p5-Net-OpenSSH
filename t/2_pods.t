#!/usr/bin/perl

use strict;
use Test::More;

plan skip_all => "Only the author needs to check that POD docs are right"
    unless eval "no warnings; getlogin eq 'salva'";

eval "use Test::Pod 1.00";
plan skip_all => "Test::Pod 1.00 required for testing POD" if $@;

all_pod_files_ok( all_pod_files( qw(blib) ) );
