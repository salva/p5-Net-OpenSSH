package Net::OpenSSH::ShellQuoter::MSWin;

use strict;
use warnings;
use Carp;

sub new { shift() }

sub quote {
    shift;
    my $arg = shift;
    if ($arg eq '') {
        return '""';
    }
    if ($arg =~ /[ \t\n\x0b"]/) {
        $arg =~ s{(\\+)(?="|\z)}{$1$1}g;
        $arg =~ s{"}{\\"}g;
        return qq("$arg");
    }
    return $arg;
}

*quote_glob = \&quote;

sub shell_fragments { wantarray ? () : '' }

1;
