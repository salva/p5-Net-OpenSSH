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

__END__

=head1 NAME

Net::OpenSSH::ShellQuoter::MSCmd - Quoter for Windows cmd.exe

=head1 DESCRIPTION

This quoter is intended for interaction with SSH servers running on
Windows which invoke the requested commands through the C<cmd.exe> shell.

Because of C<cmd.exe> not doing wildcard expansion (on Windows this
task is left to the final command), glob quoting just quotes
everything.

Some Windows servers use C<Win32::CreateProcess> to run the C<cmd.exe>
shell which runs the requested command. In that case, both the C<MSCmd>
and C<MSWin> quoters have to be chained (and BTW, order matters):

   $ssh = Net::OpenSSH->new(...,
                            remote_shell => 'MSCmd,MSWin');

Actually, C<cmd.exe> may require not quoting at all when the requested
command is a builtin (for instance, C<echo>).

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008-2014 by Salvador FandiE<ntilde>o
(sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
