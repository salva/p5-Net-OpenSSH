#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use Net::OpenSSH::ShellQuoter;
use Data::Dumper;
sub capture;
sub hexdump;
sub perldump;
sub try_shell;

my $out = `sh -c 'echo hello 2>&1'`;
plan skip_all => 'Your shell does unexpected things!'
    unless $out eq "hello\n" and $? == 0;

my $N = 200;

my @shells = grep try_shell($_), qw(sh csh bash tcsh ksh dash ash pdksh mksh zsh);
my %quoter = map { $_ => Net::OpenSSH::ShellQuoter->quoter($_) } @shells;

my @chars = ([grep /\W/, map chr, 1..130],
             [map chr, 1..130],
             [map chr, 1..130, 141..172, 141..172]);
#my @chars = grep /\w/, map chr, 1..130;

my @str = map { my $chars = $chars[rand @chars]; join('', map $chars->[rand(@$chars)], 0..rand(500)) } 1..$N;
push @str, ("\x0a","\x27");

plan tests => @str * @shells;

diag "running tests for shells @shells";
for my $shell (@shells) {
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

sub capture {
    no warnings 'io';
    open my $fh, '-|', @_ or die "unable to exec @_";
    local $/;
    my $out = <$fh>;
    close $fh;
    $out;
}

sub try_shell {
    my $shell = shift;
    my $out = eval { capture($shell, '-c', 'echo good') };
    $out and $out =~ /^good$/;
}

my $badfh;
sub badfh {
    unless ($badfh) {
        open $badfh, '>', "missquoted.txt" or return;
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
        if (/[\w!#%&'()*+,\-.\/:;<=>?[]^`{|}~]/) {
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
