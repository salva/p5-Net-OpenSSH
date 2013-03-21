package Net::OpenSSH::ShellQuoter;

use strict;
use warnings;
use Carp;

use Net::OpenSSH::ModuleLoader;

my %alias = (bash => 'POSIX',
             sh   => 'POSIX',
             ksh  => 'POSIX',
             tcsh => 'csh');

sub quoter {
    my ($class, $style) = @_;
    $style = 'POSIX' unless defined $style;
    $style = $alias{$style} if defined $alias{$style};
    $style =~ /^\w+$/ or croak "bad quoting style $style";

    my $impl = "Net::OpenSSH::ShellQuoter::$style";
    _load_module($impl);
    $impl->new
}

1;
