package Net::OpenSSH::ObjectRemote;

use strict;
use warnings;

use Moo;

with 'Object::Remote::Role::Connector::PerlInterpreter';

has net_openssh => (is => 'ro', required => 1);

sub final_perl_command {
    my $self = shift;
    my $perl_command = $self->perl_command;
    [ $self->net_openssh->make_remote_command(@$perl_command) ];
}

1;
