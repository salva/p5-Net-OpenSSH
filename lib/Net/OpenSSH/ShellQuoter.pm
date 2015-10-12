package Net::OpenSSH::ShellQuoter;

use strict;
use warnings;
use Carp;

use Net::OpenSSH::ModuleLoader;

my %alias = (bash  => 'POSIX',
             sh    => 'POSIX',
             ksh   => 'POSIX',
             ash   => 'POSIX',
             dash  => 'POSIX',
             pdksh => 'POSIX',
             mksh  => 'POSIX',
             lksh  => 'POSIX',
             zsh   => 'POSIX',
             fizsh => 'POSIX',
             posh  => 'POSIX',
             fish  => 'fish',
             tcsh  => 'csh');

sub quoter {
    my ($class, $shell) = @_;
    $shell = 'POSIX' unless defined $shell;
    return $shell if ref $shell;
    if ($shell =~ /,/) {
        require Net::OpenSSH::ShellQuoter::Chain;
        return Net::OpenSSH::ShellQuoter::Chain->chain(split /\s*,\s*/, $shell);
    }
    else {
        $shell = $alias{$shell} if defined $alias{$shell};
        $shell =~ /^\w+$/ or croak "bad quoting style $shell";
        my $impl = "Net::OpenSSH::ShellQuoter::$shell";
        _load_module($impl);
        return $impl->new;
    }
}

1;
