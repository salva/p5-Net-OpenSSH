package Net::OpenSSH::ShellQuoter;

use strict;
use warnings;
use Carp;

use Net::OpenSSH::ModuleLoader;

sub quoter {
    my ($class, $style) = @_;
    $style = 'POSIX' unless defined $style;
    $style =~ /^\w+$/ or croak "bad quoting style $style";

    my $impl = "Net::OpenSSH::ShellQuoter::$style";
    _load_module($impl);
    $impl->new
}

1;
