#!/usr/bin/perl

# This script contains a rude implementation of a custom login handler
# for password authentication.

use strict;
use warnings;

use Net::OpenSSH;

my ($host, $user, $passwd) = @ARGV;

sub mi_login_handler {
    my ($ssh, $pty, $data) = @_;
    # print "custom login handler called!";
    my $read = sysread($pty, $$data, 1024, length $$data);
    if ($read) {
        # print "buffer: >$$data<\n";
        if ($$data =~ s/.*://s) {
            print $pty "$passwd\n";
            return 1;
        }
    }
    return 0;
}

my $ssh = Net::OpenSSH->new($host, user => $user,
                            master_opts => [-o => 'NumberOfPasswordPrompts=1',
                                            -o => 'PreferredAuthentications=keyboard-interactive,password'],
                            login_handler => \&mi_login_handler);
$ssh->error and die "Unable to connect to remote machine" . $ssh->error;
$ssh->system("ls");
