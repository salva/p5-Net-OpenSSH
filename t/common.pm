use strict;
use warnings;

use Test::More;
use File::Spec;
use Socket qw(AF_UNIX SOCK_STREAM PF_UNSPEC);

sub sshd_cmd {
    my $sc_name = 'sshd';

    my @paths = qw( /usr
                    /usr/local
                    /usr/local/openssh
                    /opt/ssh
                    /opt/openssh );

    @paths = map { ("$_/sbin/sshd", "$_/bin/sshd") } @paths;

    for my $sshd (@paths) {
	return $sshd if -x $sshd;
    }
}

sub find_cmd {
    my @path = qw(/usr/bin /bin
		  /usr/local/bin
		  /usr/sbin /sbin
		  /opt/bin );

    for my $cmd (@_) {
	for my $path (@path) {
	    my $r = "$path/$cmd";
	    return $r if -x $r;
	}
    }
    undef;
}

sub shell_is_clean {
    my $shell = (getpwuid($>))[8];

    socketpair my $up, my $down, AF_UNIX, SOCK_STREAM, PF_UNSPEC or return;
    my $pid = fork;
    unless ($pid) {
        unless (defined $pid) {
            diag "fork failed: $!";
            return;
        }
        open STDIN,  '<&', $down;
        open STDOUT, '>>&', $down;
        open STDERR, '>>&', $down;

        my $pid2 = fork;
        if (defined $pid2 and not $pid2) {
            setpgrp(0, 0);
            # make bash read .bashrc on Debian systems:
            delete $ENV{SHLVL};
            $ENV{SSH_CLIENT} = "::1 12345 22";
            do { exec $shell, '-c', 'echo ok' };
        }
        exit 0;
    }
    close $down;

    my $out = do { local $/; <$up> };
    if (!close($up) or $out ne "ok\n") {
        diag "shell is not clean: \$?=$?, output...\n$out";
        return;
    }
    1
}

my @last_open_fds;

sub count_open_fds {
    @last_open_fds = ();
    if ($^O eq 'linux') {
        if (opendir my $dh, "/proc/$$/fd") {
            my $count = 0;
            while (defined(my $fd = readdir $dh)) {
                push @last_open_fds, $fd if $fd =~ /^\d+$/;
            }
            return scalar @last_open_fds;
        }
    }
    ()
}

sub dump_open_fds {
    my @ls = map { `ls -l /proc/$$/fd/$_ 2>&1` } @last_open_fds;
    join('', "Currently open flle descriptors:\n", @ls);
}

1;
