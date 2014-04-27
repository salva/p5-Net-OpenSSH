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

__END__

=head1 NAME

Net::OpenSSH::ShellQuoter::MSWin - Quoter for Win32::CreateProcess

=head1 DESCRIPTION

This quoter is intended for interaction with SSH servers running on
Windows which use the C<Win32::CreateProcess> system call to launch the
requested command.

Because of C<Win32::CreateProcess> not doing wildcard expansion, glob
quoting just quotes everything.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008-2014 by Salvador FandiE<ntilde>o
(sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
