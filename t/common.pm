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

1;
