#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use Net::OpenSSH::ShellQuoter;
use lib './t';
use common;

if ($^O =~ /MSWin/) {
    plan skip_all => 'Core functionality does not work on Windows';
}

my $alt_lang;
if ($^O =~ /^solaris/ and $ENV{LANG} =~ /\.UTF-8$/) {
    $alt_lang = $ENV{LANG};
    $alt_lang =~ s/\.UTF-8$//;
}

# use Data::Dumper;
sub capture;
sub hexdump;
sub perldump;
sub try_shell;

plan skip_all => 'Your shell does unexpected things!'
    unless shell_is_clean;

my $N = 200;

my @shells = grep try_shell($_), qw(sh csh bash tcsh ksh dash ash pdksh mksh zsh fish);
my %quoter = map { $_ => Net::OpenSSH::ShellQuoter->quoter($_) } @shells;

my @chars = ([grep /\W/, map chr, 1..130],
             [map chr, 1..130],
             [map chr, 1..130, 141..172, 141..172]);
#my @chars = grep /\w/, map chr, 1..130;

my @str = map { my $chars = $chars[rand @chars]; join('', map $chars->[rand(@$chars)], 0..rand(500)) } 1..$N;
push @str, ("\x0a","\x27");

my $broken_ksh = "\x82\x27\x3c\x7e\x7b";
push @str, $broken_ksh;

plan tests => @str * @shells;

diag "running tests for shells @shells";
for my $shell (@shells) {

    # workaround for solaris csh fixing invalid UTF8 sequences. 
    local $ENV{LANG} = $alt_lang if $shell eq 'csh' and defined $alt_lang;

    my $i = 0;
    for my $str (@str) {
        my $cmd = join ' ', map $quoter{$shell}->quote($_), "printf", "%s", $str;
        my $out = capture($shell, '-c', $cmd);
        is ($out, $str, "$shell - $i") or do {
            diag "str: >$str< cmd: >$cmd<";
            hexdump "string", $str;
            hexdump "output (shell: $shell)", $out;
            hexdump "quoted", $cmd;
            perldump "string", $str;
        };
        $i++;
    }
}

our $child_pid;
sub capture {
    no warnings 'io';
    my $pid = open my $fh, '-|', @_ or die "unable to exec @_";
    local $/;
    my $out = do {
        local $child_pid = $pid;
        <$fh>
    };
    close $fh;
    $out;
}

sub try_shell {
    my $shell = shift;
    my $ok;
    local $SIG{ALRM} = sub {
        kill KILL => $child_pid if $child_pid;
        die "timeout while waiting for shell $shell"
    };
    eval {
        eval {
            no warnings 'uninitialized';
            alarm 10;
            my $out = capture($shell, '-c', 'echo good');
            $out =~ /^good$/ or die "shell $shell not found";
            if ($shell =~ /ksh/) {
                my $version = `$shell --version 2>&1 </dev/null`;
                $version =~ /version\s+sh\s+\(AT\&T\s+Research\)/
                    and die "skipping tests for broken AT&T ksh shell";
            }
            else {
                $shell eq '!!fish' and die "TODO: add support for fish shell";
            }
        };
        alarm 0;
        die $@ if $@;
        $ok = 1;
    };
    if ($@) {
        $@ =~ s/ at .*//m;
        diag $@;
    }
    $ok;
}

my $badfh;
sub badfh {
    unless ($badfh) {
        open $badfh, '>', "misquoted.txt" or return;
        print $badfh "This file contains the strings that were not quoted properly\n\n";
    }
    $badfh;
}

sub hexdump {
    no warnings qw(uninitialized);
    my $head = shift;
    my $data = shift;
    my $fh = badfh();
    print $fh "$head:\n";
    while ($data =~ /(.{1,32})/smg) {
        my $line=$1;
        my @c= (( map { sprintf "%02x",$_ } unpack('C*', $line)),
                (("  ") x 32))[0..31];
        $line=~s/(.)/ my $c=$1; unpack("c",$c)>=32 ? $c : '.' /egms;
        print $fh "#> ", join(" ", @c, '|', $line), "\n";
    }
}

sub perldump {
    my $head = shift;
    my $data = shift;
    my $fh = badfh();
    my @c;
    for (split //, $data) {
        if (/[\w!#%&'()*+,\-.\/:;<=>?\[\]^`{|}~]/) {
            push @c, $_;
        }
        elsif (/["\$\@\\]/) {
            push @c, "\\$_";
        }
        else {
            push @c, sprintf "\\x%02x", ord $_;
        }
    }
    print $fh "$head: \"", @c, "\"\n";
}
