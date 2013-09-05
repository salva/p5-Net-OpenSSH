package Net::OpenSSH::ShellQuoter::Chain;

use strict;
use warnings;

use Net::OpenSSH::ShellQuoter;

sub chain {
    my $class = shift;
    my @quoters = map Net::OpenSSH::ShellQuoter->quoter($_), reverse @_;
    my $self = \@quoters;
    bless $self, $class;
    $self;
}

sub quote {
    my ($self, $arg) = @_;
    $arg = $_->quote($arg) for @$self;
    $arg;
}

sub quote_glob {
    my ($self, $arg) = @_;
    if (@$self) {
        $arg = $self->[0]->quote_glob($arg);
        $arg = $self->[$_]->quote($arg) for 1..$#$self;
    }
    $arg
}

sub shell_fragments {
    my $self = shift;
    @$self or return (wantarray ? () : '');
    $self->[-1]->shell_fragments(@_)
}


1;
