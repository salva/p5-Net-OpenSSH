package Net::OpenSSH::ShellQuoter::MSCmd;

use strict;
use warnings;
use Carp;

sub new { shift() }

sub quote {
    shift;
    my $arg = shift;
    if ($arg =~ /[\r\n\0]/) {
        croak "can't quote newlines to pass through MS cmd.exe";
    }
    $arg =~ s/([()%!^"<>&|])/^$1/g;
    $arg;
}

*quote_glob = \&quote;

my %fragments = ( stdin_discard             => '<NUL:',
                  stdout_discard            => '>NUL:',
                  stderr_discard            => '2>NUL:',
                  stdout_and_stderr_discard => '>NUL: 2>&1',
                  stderr_to_stdout          => '2>&1' );

sub shell_fragments {
    shift;
    my @f = grep defined, @fragments{@_};
    wantarray ? @f : join(' ', @f);
}

1;
