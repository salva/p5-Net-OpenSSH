#!/usr/bin/perl

use strict;
use warnings;
use Test::More;

eval "use Test::Spelling";
plan skip_all => "Test::Spelling required for testing POD spelling" if $@;

my @ignore = ("Fandi\xf1o", "API", "CPAN", "GitHub", "bugtracking",
              "IETF", "OpenSSH", "FreeBSD", "OpenBSD", "LF", "POSIX",
              "plink", "PuTTY", "SFTP", "STDERR", "STDOUT", "STDIN",
              "UTF", "VMS", "Incrementing", "autodie",
              "autodisconnect", "backend", "canonicalise", "de",
              "facto", "dualvar", "hardcode", "hardlink", "filename",
              "libssh", "login", "passphrase", "pipelined",
              "plugable", "pre", "realpath", "runtime", "sftp",
              "stderr", "subdirectories", "tectia", "username",
              "unix", "versa", "wildcard", "wildcards", "wishlist",
              "deserialization", "AFS", "AIX", "Bourne", "Ctrl", 
              "MaxSessions", "NetBSD", "OpenVMS", "RPC", "SIGPIPE",
              "Solaris", "StrictHostKeyChecking", "TCP", "TODO",
              "TheSchwartz", "UX", "Wikibook", "async", "bwlimit",
              "latin", "hexdumps", "mux", "perlish", "setpgrp",
              "socketpair", "sshd", "unicode", "unixen", "natively",
              "pty", "quoter", "quoters", "refactor", "reinstalled",
              "subcommands", "unmounts", "unwritable", "ktruss",
              "strace", "tusc", "cmd", "exe");

local $ENV{LC_ALL} = 'C';
add_stopwords(@ignore);
all_pod_files_spelling_ok();

