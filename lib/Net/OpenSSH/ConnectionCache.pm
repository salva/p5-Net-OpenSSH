package Net::OpenSSH::ConnectionCache;

use strict;
use warnings;

use Net::OpenSSH;
use Net::OpenSSH::Constants qw(:error);

use Data::Dumper;
use Scalar::Util qw(weaken);

our $MAX_SIZE = 20;
our %cache;

sub _factory {
    my $class = shift;
    my %opts = @_;
    my $dump = Data::Dumper->new([\%opts], ['s']);
    $dump->Indent(0);
    $dump->Sortkeys(1);
    $dump->Deepcopy(1);
    my $signature = $dump->Dump;
    my $ssh = $cache{$signature};
    if ($ssh and $ssh->error != OSSH_MASTER_FAILED) {
        if ($opts{async} or $ssh->wait_for_master) {
            return $cache{$signature} = $ssh;
        }
    }
    if ($MAX_SIZE <= keys %cache) {
        for (keys %cache) {
            $ssh = $cache{$_};
            $ssh or $ssh->error != OSSH_MASTER_FAILED or delete $cache{$_}
        }
        for (keys %cache) {
            last if ($MAX_SIZE <= keys %cache);
            weaken $cache{$_};
            if (defined $cache{$_}) {
                $cache{$_} = $cache{$_}; # unweaken
            }
            else {
                delete $cache{$_};
            }
        }
    }
    local $Net::OpenSSH::FACTORY;
    $cache{$signature} = $class->new(@_);
}

$Net::OpenSSH::FACTORY = \&_factory;

sub clean_cache { %cache = () }

END { %cache = () }

1;

__END__

=head1 NAME

Net::OpenSSH::ConnectionCache - cache and reuse SSH connections transparently

=head1 SYNOPSIS

  use Net::OpenSSH;
  use Net::OpenSSH::ConnectionCache;

  for (1..10) {
    my $ssh = Net::OpenSSH->new($host);
    $ssh->system("$cmd $_");
  }

=head1 DESCRIPTION

This module installs a C<$Net::OpenSSH::FACTORY> hook implementing a
SSH connection caching scheme.

C<$Net::OpenSSH::ConnectionCache::MAX_SIZE> controls the cache
size. Once as many connections are allocated, the module will try to
free any of them before allocating a new one.

The function C<clean_cache> makes the module forget (and close) all
the cached connections:

  Net::OpenSSH::ConnectionCache::clean_cache();

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011, 2014 by Salvador FandiE<ntilde>o
(sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
