package Net::OpenSSH::ShellQuoter::POSIX;

use strict;
use warnings;
use Carp;

sub new { __PACKAGE__ }

my $noquote_class = '.\\w/\\-@,:';
my $glob_class    = '*?\\[\\],{}:!^~';

sub quote {
    shift;
    my $quoted = join '',
        map { ( m|\A'\z|                  ? "\\'"    :
                m|\A'|                    ? "\"$_\"" :
                m|\A[$noquote_class]+\z|o ? $_       :
                                          "'$_'"   )
          } split /('+)/, $_[0];
    length $quoted ? $quoted : "''";
}


sub quote_glob {
    shift;
    my $arg = shift;
    my @parts;
    while ((pos $arg ||0) < length $arg) {
        if ($arg =~ m|\G('+)|gc) {
            push @parts, (length($1) > 1 ? "\"$1\"" : "\\'");
        }
        elsif ($arg =~ m|\G([$noquote_class$glob_class]+)|gco) {
            push @parts, $1;
        }
        elsif ($arg =~ m|\G(\\[$glob_class\\])|gco) {
            push @parts, $1;
        }
        elsif ($arg =~ m|\G\\|gc) {
            push @parts, '\\\\'
        }
        elsif ($arg =~ m|\G([^$glob_class\\']+)|gco) {
            push @parts, "'$1'";
        }
        else {
            require Data::Dumper;
            $arg =~ m|\G(.+)|gc;
            die "Internal error: unquotable string:\n". Data::Dumper::Dumper($1) ."\n";
        }
    }
    my $quoted = join('', @parts);
    length $quoted ? $quoted : "''";
}

my %fragments = ( discard_stding            => '</dev/null',
                  discard_stdout            => '>/dev/null',
                  discard_stderr            => '2>/dev/null',
                  stderr_to_stdout          => '2>&1',
                  stdout_and_stderr_discard => '>/dev/null 2>&1' );

sub shell_fragments {
    shift;
    my @f = join ' ', grep defined, @fragments{@_};
    wantarray ? @f : join(' ', @f);
}

1;
