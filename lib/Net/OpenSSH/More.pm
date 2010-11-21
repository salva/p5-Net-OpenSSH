_sub_options scp_cat => qw(); # stderr_discard stderr_fh stderr_file);

sub scp_cat {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $glob = delete $opts{glob};
    my $recursive = delete $opts{recursive};
    my $quiet = delete $opts{quiet};
    $quiet = 1 unless defined $quiet;

    @_ >= 1 or croak 'Usage: $ssh->scp_cat(\%opts, $remote_fn1, $remote_fn2...)';
    my @src = $self->_quote_args({ quote_args => 1,
                                   glob_quoting => $glob }, @_);
    _croak_bad_options %opts;

    my $pid = open(my $cat, '-|');
    unless ($pid) {
        unless (defined $pid) {
            $self->_set_error(OSSH_SLAVE_FAILED, "unable to fork new ssh slave: $!");
            return ();
        }

        my @opts = '-f';
        push @opts, '-r' if $recursive;

        my ($in, $out, $pid2) = $self->open2(\%opts,
                                             scp => '-f',
                                             ($recursive ? '-r' : ()),
                                             '--',
                                             @src)
            or POSIX::_exit(1);

        my $on_error;
        while(1) {
            unless ($on_error) {
                $debug and $debug & 256 and _debug "sending 0";
                syswrite($in, "\x00") == 1 or POSIX::_exit(1);
            }

            my $switch;
            sysread($out, $switch, 1) or POSIX::_exit(0);
            $on_error = (ord($switch) <= 1);
            $debug and $debug & 256 and _debug "switch: $switch, on_error: $on_error";


            my $buf = '';
            $debug and $debug & 256 and _debug "reading header";
            do {
                sysread($out, $buf, ($on_error ? 1 : 10000), length $buf) or POSIX::_exit(1);
            } until $buf =~ /\x0A/;

            $debug and $debug & 256 and _debug "switch: $switch, header: $buf";

            if ($on_error) {
                print STDERR $buf unless $quiet;
            }
            elsif ($switch eq 'C') {
                my $size = (split /\s+/, $buf)[1];
                $debug and $debug & 256 and _debug "transferring file of size $size";
                    syswrite($in, "\x00") == 1 or POSIX::_exit(1);
                while ($size) {
                    my $read = sysread($out, $buf, ($size > 10000 ? 10000 : $size)) or POSIX::_exit(1);
                    $size -= $read;
                    if ($debug and $debug & 256) {
                        _debug "$read bytes read, $size remaining";
                        $debug & 128 and _hexdump $buf;
                    }
                    print $buf;
                }
                sysread($out, $buf, 1) == 1 or POSIX::_exit(1);
                $debug and $debug & 256 and _debug "file tail read >>$buf<<";
                $buf eq "\x00" or POSIX::_exit(3);
            }
            elsif ($switch eq 'D') {
                # directory, do nothing!
            }
            elsif ($switch eq 'E') {
                # do nothing!
            }
            else {
                $debug and $debug & 256 and _debug "unknown command >>$switch<<";
                POSIX::_exit(1);
            }
        }
    }
    wantarray ? ($cat, $pid) : $cat;
}

=item $ssh->scp_cat(\%opts, $remote1, $remote2, ...)

this command is equivalent to

  $ssh->pipe_out(\%opts, 'cat', $remote1, $remote2, ...)

but built on top of C<scp> that is usually available on most operative
system and not just on Unix and alike.

The accepted options are:

=over 4

=item glob => 1

allows remote expansion of wildcards in the given source filenames

=item recursive => 1

recursively searchs for files inside any given directory

=item quiet => 0

prints errors to STDERR

=back

