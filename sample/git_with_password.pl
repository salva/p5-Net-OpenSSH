#!/usr/bin/perl

use strict;
use warnings;

use Net::OpenSSH;

@ARGV or die <<EOU;
Usage:
  $0 <ssh_target> <git_command> [<arg1> [<arg2> [...]]]

For instance:
  $0 kkabuto:sayaka\@mazingerz.pplab.or.jp clone ssh://kkabuto\@mazingerz.pplab.or.jp/home/kkabuto/pilder-linux

EOU

my $target = shift @ARGV; # password:user@host

my $ssh = Net::OpenSSH->new($target);
$ssh->die_on_error("Unable to connect to $target");

$ENV{GIT_SSH} = 'git_ssh_through_mux.pl';
$ENV{SSH_MUX} = $ssh->get_ctl_path;

system 'env';

system git => @ARGV;
