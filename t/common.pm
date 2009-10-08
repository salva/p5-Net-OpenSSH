use strict;
use warnings;

use File::Spec;

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

1;
