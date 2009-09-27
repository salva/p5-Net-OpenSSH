package Net::OpenSSH::Constants;

our $VERSION = '0.39';

use strict;
use warnings;
use Carp;

require Exporter;
our @ISA = qw(Exporter);
our %EXPORT_TAGS = (error => []);

my %error = ( OSSH_MASTER_FAILED => 1,
              OSSH_SLAVE_FAILED => 2,
              OSSH_SLAVE_PIPE_FAILED => 3,
	      OSSH_SLAVE_TIMEOUT => 4,
	      OSSH_SLAVE_CMD_FAILED => 5,
	      OSSH_SLAVE_SFTP_FAILED => 6
            );

for my $key (keys %error) {
    no strict 'refs';
    my $value = $error{$key};
    *{$key} = sub () { $value };
    push @{$EXPORT_TAGS{error}}, $key
}

our @EXPORT_OK = map { @{$EXPORT_TAGS{$_}} } keys %EXPORT_TAGS;
$EXPORT_TAGS{all} = [@EXPORT_OK];

1;

__END__

=head1 NAME

Net::OpenSSH::Constants - Constant definitions for Net::OpenSSH

=head1 SYNOPSIS

  use Net::OpenSSH::Constants qw(:error);

=head1 DESCRIPTION

This module exports the following constants:

=over 4

=item :error

  OSSH_MASTER_FAILED - some error related to the master SSH connection happened
  OSSH_SLAVE_FAILED - some error related to a slave SSH connection happened
  OSSH_SLAVE_PIPE_FAILED - unable to create pipe to communicate with slave process
  OSSH_SLAVE_TIMEOUT - slave process timeout
  OSSH_SLAVE_CMD_FAILED - child process exited with a non zero status
  OSSH_SLAVE_SFTP_FAILED - creation of SFTP client failed

=back

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008, 2009 by Salvador FandiE<ntilde>o (sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
