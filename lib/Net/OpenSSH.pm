package Net::OpenSSH;

our $VERSION = '0.58_04';

use strict;
use warnings;

our $debug ||= 0;

our $FACTORY;

use Carp qw(carp croak);
use POSIX qw(:sys_wait_h);
use Socket;
use File::Spec;
use Cwd ();
use Scalar::Util ();
use Errno ();
use Net::OpenSSH::Constants qw(:error);

my $thread_generation = 0;

sub CLONE { $thread_generation++ };

sub _debug { print STDERR '# ', (map { defined($_) ? $_ : '<undef>' } @_), "\n" }

sub _debug_dump {
    require Data::Dumper;
    local $Data::Dumper::Terse = 1;
    local $Data::Dumper::Indent = 0;
    my $head = shift;
    _debug("$head: ", Data::Dumper::Dumper(@_));
}

sub _hexdump {
    no warnings qw(uninitialized);
    my $data = shift;
    while ($data =~ /(.{1,32})/smg) {
        my $line=$1;
        my @c= (( map { sprintf "%02x",$_ } unpack('C*', $line)),
                (("  ") x 32))[0..31];
        $line=~s/(.)/ my $c=$1; unpack("c",$c)>=32 ? $c : '.' /egms;
        print STDERR "#> ", join(" ", @c, '|', $line), "\n";
    }
}

{
    my %good;

    sub _sub_options {
        my $sub = shift;
        $good{__PACKAGE__ . "::$sub"} = { map { $_ => 1 } @_ };
    }

    sub _croak_bad_options (\%) {
        my $opts = shift;
        if (%$opts) {
	    my $sub = (caller 1)[3];
            my $good = $good{$sub};
            my @keys = ( $good ? grep !$good->{$_}, keys %$opts : keys %$opts);
            if (@keys) {
                croak "Invalid or bad combination of options ('" . CORE::join("', '", @keys) . "')";
            }
        }
    }
}

sub _tcroak {
    if (${^TAINT} > 0) {
	push @_, " while running with -T switch";
        goto &croak;
    }
    if (${^TAINT} < 0) {
	push @_, " while running with -t switch";
        goto &carp;
    }
}

sub _catch_tainted_args {
    my $i;
    for (@_) {
        next unless $i++;
        if (Scalar::Util::tainted($_)) {
            my (undef, undef, undef, $subn) = caller 1;
            my $msg = ( $subn =~ /::([a-z]\w*)$/
                        ? "Insecure argument '$_' on '$1' method call"
                        : "Insecure argument '$_' on method call" );
            _tcroak($msg);
        }
        elsif (ref($_) eq 'HASH') {
            for (grep Scalar::Util::tainted($_), values %$_) {
		my (undef, undef, undef, $subn) = caller 1;
		my $msg = ( $subn =~ /::([a-z]\w*)$/
			    ? "Insecure argument on '$1' method call"
			    : "Insecure argument on method call" );
		_tcroak($msg);
            }
        }
    }
}

sub _set_error {
    my $self = shift;
    my $code = shift || 0;
    my $err = $self->{_error} = ( $code
                                  ? Scalar::Util::dualvar($code, join(': ', @{$self->{_error_prefix}},
                                                                      (@_ ? @_ : "Unknown error $code")))
                                  : 0 );
    $debug and $debug & 1 and _debug "set_error($code - $err)";
    return $err
}

my $check_eval_re = do {
    my $path = quotemeta $INC{"Net/OpenSSH.pm"};
    qr/at $path line \d+.$/
};

sub _check_eval_ok {
    my ($self, $code) = @_;
    if ($@) {
        my $err = $@;
        $err =~ s/$check_eval_re//;
        $self->_set_error($code, $err);
        return;
    }
    1
}

sub _or_set_error {
    my $self = shift;
    $self->{_error} or $self->_set_error(@_);
}

sub _first_defined { defined && return $_ for @_; return }

my $obfuscate = sub {
    # just for the casual observer...
    my $txt = shift;
    $txt =~ s/(.)/chr(ord($1) ^ 47)/ges
        if defined $txt;
    $txt;
};

my $deobfuscate = $obfuscate;

# regexp from Regexp::IPv6
my $IPv6_re = qr((?-xism::(?::[0-9a-fA-F]{1,4}){0,5}(?:(?::[0-9a-fA-F]{1,4}){1,2}|:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}|:)|(?::(?:[0-9a-fA-F]{1,4})?|(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})?|))|(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[0-9a-fA-F]{1,4}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){0,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,2}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,3}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,4}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))));

sub parse_connection_opts {
    my ($class, $opts) = @_;
    my ($user, $passwd, $ipv6, $host, $port, $host_squared);

    my $target = delete $opts->{host};
    defined $target or croak "mandatory host argument missing";

    ($user, $passwd, $ipv6, $host, $port) =
        $target =~ m{^
                       \s*               # space
                       (?:
                         ([^\@:]+)       # username
                         (?::(.*))?      # : password
                         \@              # @
                       )?
                       (?:               # host
                          (              #   IPv6...
                            \[$IPv6_re\] #     [IPv6]
                            |            #     or
                            $IPv6_re     #     IPv6
                          )
                          |              #   or
                          ([^\[\]\@:]+)  #   hostname / ipv4
                       )
                       (?::([^\@:]+))?   # port
                       \s*               # space
                     $}ix
                or croak "bad host/target '$target' specification";

    if (defined $ipv6) {
        ($host) = $ipv6 =~ /^\[?(.*?)\]?$/;
        $host_squared = "[$host]";
    }
    else {
        $host_squared = $host;
    }

    $user = delete $opts->{user} unless defined $user;
    $port = delete $opts->{port} unless defined $port;
    $passwd = delete $opts->{passwd} unless defined $passwd;
    $passwd = delete $opts->{password} unless defined $passwd;

    wantarray and return ($host, $port, $user, $passwd, $host_squared);

    my %r = ( user => $user,
              password => $passwd,
              host => $host,
              host_squared => $host_squared,
              port => $port );
    $r{ipv6} = 1 if defined $ipv6;
    return \%r;
}

sub new {
    ${^TAINT} and &_catch_tainted_args;

    my $class = shift;
    @_ & 1 and unshift @_, 'host';

    return $FACTORY->($class, @_) if defined $FACTORY;

    my %opts = @_;

    my $external_master = delete $opts{external_master};
    # reuse_master is an obsolete alias:
    $external_master = delete $opts{reuse_master} unless defined $external_master;

    if (not defined $opts{host} and defined $external_master) {
        $opts{host} = 'UNKNOWN';
    }

    my ($host, $port, $user, $passwd, $host_squared) = $class->parse_connection_opts(\%opts);

    my ($passphrase, $key_path, $login_handler);

    unless (defined $passwd) {
        $key_path = delete $opts{key_path};
        $passwd = delete $opts{passphrase};
        if (defined $passwd) {
            $passphrase = 1;
        }
        else {
            $login_handler = delete $opts{login_handler};
        }
    }

    my $batch_mode = delete $opts{batch_mode};
    my $ctl_path = delete $opts{ctl_path};
    my $ctl_dir = delete $opts{ctl_dir};
    my $proxy_command = delete $opts{proxy_command};
    my $gateway = delete $opts{gateway} unless defined $proxy_command;
    my $ssh_cmd = _first_defined delete $opts{ssh_cmd}, 'ssh';
    my $rsync_cmd = _first_defined delete $opts{rsync_cmd}, 'rsync';
    my $scp_cmd = delete $opts{scp_cmd};
    my $sshfs_cmd = _first_defined delete $opts{sshfs_cmd}, 'sshfs';
    my $sftp_server_cmd = _first_defined delete $opts{sftp_server_cmd},
                                         '/usr/lib/openssh/sftp-server';
    my $timeout = delete $opts{timeout};
    my $kill_ssh_on_timeout = delete $opts{kill_ssh_on_timeout};
    my $strict_mode = _first_defined delete $opts{strict_mode}, 1;
    my $async = delete $opts{async};
    my $target_os = _first_defined delete $opts{target_os}, 'unix';
    my $expand_vars = delete $opts{expand_vars};
    my $vars = _first_defined delete $opts{vars}, {};
    my $default_encoding = delete $opts{default_encoding};
    my $default_stream_encoding =
        _first_defined delete $opts{default_stream_encoding}, $default_encoding;
    my $default_argument_encoding =
        _first_defined delete $opts{default_argument_encoding}, $default_encoding;
    my $forward_agent = delete $opts{forward_agent};
    $forward_agent and $passphrase and
        croak "agent forwarding can not be used when a passphrase has also been given";

    my ($master_opts, @master_opts,
        $master_stdout_fh, $master_stderr_fh,
	$master_stdout_discard, $master_stderr_discard);
    unless ($external_master) {
        ($master_stdout_fh = delete $opts{master_stdout_fh} or
         $master_stdout_discard = delete $opts{master_stdout_discard});

        ($master_stderr_fh = delete $opts{master_stderr_fh} or
         $master_stderr_discard = delete $opts{master_stderr_discard});

        $master_opts = delete $opts{master_opts};
        if (defined $master_opts) {
            if (ref $master_opts) {
                @master_opts = @$master_opts;
            }
            else {
                carp "'master_opts' argument looks like if it should be splited first"
                    if $master_opts =~ /^-\w\s+\S/;
                @master_opts = $master_opts;
            }
        }
    }

    my $default_ssh_opts = delete $opts{default_ssh_opts};
    carp "'default_ssh_opts' argument looks like if it should be splited first"
        if defined $default_ssh_opts and not ref $default_ssh_opts and $default_ssh_opts =~ /^-\w\s+\S/;

    my ($default_stdout_fh, $default_stderr_fh, $default_stdin_fh,
	$default_stdout_file, $default_stderr_file, $default_stdin_file,
	$default_stdout_discard, $default_stderr_discard, $default_stdin_discard);

    $default_stdout_file = (delete $opts{default_stdout_discard}
			    ? '/dev/null'
			    : delete $opts{default_stdout_file});
    $default_stdout_fh = delete $opts{default_stdout_fh}
	unless defined $default_stdout_file;

    $default_stderr_file = (delete $opts{default_stderr_discard}
			    ? '/dev/null'
			    : delete $opts{default_stderr_file});
    $default_stderr_fh = delete $opts{default_stderr_fh}
	unless defined $default_stderr_file;

    $default_stdin_file = (delete $opts{default_stdin_discard}
			    ? '/dev/null'
			    : delete $opts{default_stdin_file});
    $default_stdin_fh = delete $opts{default_stdin_fh}
	unless defined $default_stdin_file;

    _croak_bad_options %opts;

    my @ssh_opts;
    # TODO: are those options really requiered or just do they eat on
    # the command line limited length?
    push @ssh_opts, -l => $user if defined $user;
    push @ssh_opts, -p => $port if defined $port;

    my $home = do {
	local $SIG{__DIE__};
	local $@;
	eval { Cwd::realpath((getpwuid $>)[7]) }
    };

    if (${^TAINT}) {
	($home) = $home =~ /^(.*)$/;
	Scalar::Util::tainted($ENV{PATH}) and
		_tcroak('Insecure $ENV{PATH}');
    }

    my $self = { _error => 0,
		 _error_prefix => [],
		 _perl_pid => $$,
                 _thread_generation => $thread_generation,
                 _ssh_cmd => $ssh_cmd,
		 _scp_cmd => $scp_cmd,
		 _rsync_cmd => $rsync_cmd,
                 _sshfs_cmd => $sshfs_cmd,
                 _sftp_server_cmd => $sftp_server_cmd,
                 _pid => undef,
                 _host => $host,
		 _host_squared => $host_squared,
                 _user => $user,
                 _port => $port,
                 _passwd => $obfuscate->($passwd),
                 _passphrase => $passphrase,
                 _key_path => $key_path,
                 _login_handler => $login_handler,
                 _timeout => $timeout,
                 _proxy_command => $proxy_command,
                 _gateway_args => $gateway,
                 _kill_ssh_on_timeout => $kill_ssh_on_timeout,
                 _batch_mode => $batch_mode,
                 _home => $home,
                 _forward_agent => $forward_agent,
                 _external_master => $external_master,
                 _default_ssh_opts => $default_ssh_opts,
		 _default_stdin_fh => $default_stdin_fh,
		 _default_stdout_fh => $default_stdout_fh,
		 _default_stderr_fh => $default_stderr_fh,
		 _master_stdout_fh => $master_stdout_fh,
		 _master_stderr_fh => $master_stderr_fh,
		 _master_stdout_discard => $master_stdout_discard,
		 _master_stderr_discard => $master_stderr_discard,
		 _target_os => $target_os,
                 _default_stream_encoding => $default_stream_encoding,
                 _default_argument_encoding => $default_argument_encoding,
		 _expand_vars => $expand_vars,
		 _vars => $vars,
               };
    bless $self, $class;

    # default file handles are opened so late in order to have the
    # $self object to report errors
    $self->{_default_stdout_fh} = $self->_open_file('>', $default_stdout_file)
	if defined $default_stdout_file;
    $self->{_default_stderr_fh} = $self->_open_file('>', $default_stderr_file)
	if defined $default_stderr_file;
    $self->{_default_stdin_fh} = $self->_open_file('<', $default_stdin_file)
	if defined $default_stdin_file;

    if ($self->error == OSSH_SLAVE_PIPE_FAILED) {
        $self->_set_error(OSSH_MASTER_FAILED,
                          "Unable to create default slave stream: " . $self->error);
        return $self;
    }

    $self->{_ssh_opts} = [$self->_expand_vars(@ssh_opts)];
    $self->{_master_opts} = [$self->_expand_vars(@master_opts)];

    $ctl_path = $self->_expand_vars($ctl_path);
    $ctl_dir = $self->_expand_vars($ctl_dir);

    unless (defined $ctl_path) {
        $external_master and croak "external_master is set but ctl_path is not defined";

        unless (defined $ctl_dir) {
            unless (defined $self->{_home}) {
                $self->_set_error(OSSH_MASTER_FAILED, "unable to determine home directory for uid $>");
                return $self;
            }

            $ctl_dir = File::Spec->catdir($self->{_home}, ".libnet-openssh-perl");
        }

	my $old_umask = umask 077;
        mkdir $ctl_dir;
	umask $old_umask;
        unless (-d $ctl_dir) {
            $self->_set_error(OSSH_MASTER_FAILED, "unable to create ctl_dir $ctl_dir");
            return $self;
        }

        my $target = join('-', grep defined, $user, $host, $port);

        for (1..10) {
            $ctl_path = File::Spec->join($ctl_dir, sprintf("%s-%d-%d", substr($target, 0, 20), $$, rand(1e6)));
            last unless -e $ctl_path
        }
        if (-e $ctl_path) {
            $self->_set_error(OSSH_MASTER_FAILED,
                              "unable to find unused name for ctl_path inside ctl_dir $ctl_dir");
            return $self;
        }
    }
    $ctl_dir = File::Spec->catpath((File::Spec->splitpath($ctl_path))[0,1], "");
    $debug and $debug & 2 and _debug "ctl_path: $ctl_path, ctl_dir: $ctl_dir";

    if ($strict_mode and !$self->_is_secure_path($ctl_dir)) {
 	$self->_set_error(OSSH_MASTER_FAILED, "ctl_dir $ctl_dir is not secure");
 	return $self;
    }

    $self->{_ctl_path} = $ctl_path;

    if ($external_master) {
        $self->_wait_for_master($async, 1);
    }
    else {
        $self->_connect($async);
    }
    $self;
}

sub get_user { shift->{_user} }
sub get_host { shift->{_host} }
sub get_port { shift->{_port} }
sub get_master_pid { shift->{_pid} }
sub get_ctl_path { shift->{_ctl_path} }
sub get_expand_vars { shift->{_expand_vars} }

sub set_expand_vars {
    my $self = shift;
    $self->{_expand_vars} = (shift(@_) ? 1 : 0);
}

sub set_var {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my $k = shift;
    $k =~ /^(?:USER|HOST|PORT)$/
	and croak "internal variable %$k% can not be set";
    $self->{_vars}{$k} = shift;
}

sub get_var {
    my ($self, $k) = @_;
    my $v = ( $k =~ /^(?:USER|HOST|PORT)$/
	      ? $self->{lc "_$k"}
	      : $self->{_vars}{$k} );
    (defined $v ? $v : '');
}

sub _expand_vars {
    my ($self, @str) = @_;
    if (ref $self and $self->{_expand_vars}) {
	for (@str) {
	    s{%(\w*)%}{length ($1) ? $self->get_var($1) : '%'}ge
		if defined $_;
	}
    }
    wantarray ? @str : $str[0]
}

sub error { shift->{_error} }

sub die_on_error {
    my $ssh = shift;
    $ssh->{_error} and croak(@_ ? "@_: $ssh->{_error}" : $ssh->{_error});
}


sub _is_secure_path {
    my ($self, $path) = @_;
    my @parts = File::Spec->splitdir(Cwd::realpath($path));
    my $home = $self->{_home};
    for my $last (reverse 0..$#parts) {
        my $dir = File::Spec->catdir(@parts[0..$last]);
        unless (-d $dir) {
            $debug and $debug & 2 and _debug "$dir is not a directory";
            return undef;
        }
        my ($mode, $uid) = (stat $dir)[2, 4];
        $debug and $debug & 2 and _debug "_is_secure_path(dir: $dir, file mode: $mode, file uid: $uid, euid: $>";
        return undef unless(($uid == $> or $uid == 0 ) and (($mode & 022) == 0 or ($mode & 01000)));
        return 1 if (defined $home and $home eq $dir);
    }
    return 1;
}

sub _make_ssh_call {
    my $self = shift;
    my @before = @{shift || []};
    my @args = ($self->{_ssh_cmd}, @before,
		-S => $self->{_ctl_path},
                @{$self->{_ssh_opts}}, $self->{_host},
                '--',
                (@_ ? "@_" : ()));
    $debug and $debug & 8 and _debug_dump 'call args' => \@args;
    @args;
}

sub _scp_cmd {
    my $self = shift;
    $self->{_scp_cmd} ||= do {
	my $scp = $self->{_ssh_cmd};
	$scp =~ s/ssh$/scp/i or croak "scp command name not set";
	$scp;
    }
}

sub _make_scp_call {
    my $self = shift;
    my @before = @{shift || []};
    my @args = ($self->_scp_cmd, @before,
		-o => "ControlPath=$self->{_ctl_path}",
                -S => $self->{_ssh_cmd},
                (defined $self->{_port} ? (-P => $self->{_port}) : ()),
                '--', @_);

    $debug and $debug & 8 and _debug_dump 'scp call args' => \@args;
    @args;
}

sub _rsync_quote {
    my ($self, @args) = @_;
    for (@args) {
	if (/['"\s]/) {
	    s/"/""/g;
	    $_ = qq|"$_"|;
	}
	s/%/%%/;
    }
    wantarray ? @args : join(' ', @args);
}

sub _make_rsync_call {
    my $self = shift;
    my $before = shift;
    my @transport = ($self->{_ssh_cmd}, @$before,
                    -S => $self->{_ctl_path});
    my $transport = $self->_rsync_quote(@transport);
    my @args = ( $self->{_rsync_cmd},
		 -e => $transport,
		 @_);

    $debug and $debug & 8 and _debug_dump 'rsync call args' => \@args;
    @args;
}

sub _make_tunnel_call {
    @_ == 4 or croak "bad number of arguments for creating a tunnel";
    my $self = shift;
    my @before = @{shift||[]};
    my $dest = join(':', @_);
    push @before, "-W$dest";
    my @args = $self->_make_ssh_call(\@before);
    $debug and $debug & 8 and _debug_dump 'tunnel call args' => \@args;
    @args;
}

sub master_exited {
    my $self = shift;
    my $pid = delete $self->{_pid};
    delete $self->{_wfm_state};
    $self->_set_error(OSSH_MASTER_FAILED, "master ssh connection broken");
    undef;
}

sub _kill_master {
    my $self = shift;
    my $pid = delete $self->{_pid};
    $debug and $debug & 32 and _debug '_kill_master: ', $pid;
    if ($pid and $self->{_perl_pid} == $$ and $self->{_thread_generation} == $thread_generation) {
	local $SIG{CHLD} = sub {};
        for my $sig (0, 0, 'TERM', 'TERM', 'TERM', 'KILL', 'KILL') {
            if ($sig) {
		$debug and $debug & 32 and _debug "killing master with signal $sig";
		kill $sig, $pid
		    or return;
	    }
	    for (0..5) {
		my $r = waitpid($pid, WNOHANG);
                $debug and $debug & 32 and _debug "waitpid(master: $pid) => pid: $r, rc: $!";
		return if ($r == $pid or $! == Errno::ECHILD);
		select(undef, undef, undef, 0.2);
	    }
        }
	warn "unable to kill SSH master connection (pid: $pid)";
    }
}

sub _check_is_system_fh {
    my ($name, $fh) = @_;
    my $fn = fileno(defined $fh ? $fh : $name);
    defined $fn and $fn >= 0 and return;
    croak "child process $name is not a real system file handle";
}

sub _master_redirect {
    my $self = shift;
    my $uname = uc shift;
    my $name = lc $uname;

    no strict 'refs';
    if ($self->{"_master_${name}_discard"}) {
	open *$uname, '>>', '/dev/null';
    }
    else {
	my $fh = $self->{"_master_${name}_fh"};
	$fh = $self->{"_default_${name}_fh"} unless defined $fh;
	if (defined $fh) {
	    _check_is_system_fh $uname => $fh;
	    if (fileno $fh != fileno *$uname) {
		open *$uname, '>>&', $fh or POSIX::_exit(255);
	    }
	}
    }
}

sub _connect {
    my ($self, $async) = @_;
    $self->_set_error;

    my $timeout = int((($self->{_timeout} || 90) + 2)/3);
    my @master_opts = (@{$self->{_master_opts}},
                       -o => "ServerAliveInterval=$timeout",
                       '-x2MN');

    my ($mpty, $use_pty, $pref_auths);
    $use_pty = 1 if defined $self->{_login_handler};
    if (defined $self->{_passwd}) {
        $use_pty = 1;
        $pref_auths = ($self->{_passphrase}
                       ? 'publickey'
                       : 'keyboard-interactive,password');
        push @master_opts, -o => 'NumberOfPasswordPrompts=1';
    }
    elsif ($self->{_batch_mode}) {
        push @master_opts, -o => 'BatchMode=yes';
    }

    if (defined $self->{_key_path}) {
        $pref_auths = 'publickey';
        push @master_opts, -i => $self->{_key_path};
    }

    if (defined $self->{_forward_agent}) {
        push @master_opts, ($self->{_forward_agent} ? '-A' : '-a');
    }

    my $proxy_command = $self->{_proxy_command};

    my $gateway;
    if (my $gateway_args = $self->{_gateway_args}) {
        if (ref $gateway_args eq 'HASH') {
            _load_module('Net::OpenSSH::Gateway');
            my $errors;
            unless ($gateway = Net::OpenSSH::Gateway->find_gateway(errors => $errors,
                                                                   host => $self->{_host}, port => $self->{_port},
                                                                   %$gateway_args)) {
                $self->_set_error(OSSH_MASTER_FAILED, 'Unable to build gateway object', join(', ', @$errors));
                return undef;
            }
        }
        else {
            $gateway = $gateway_args
        }
        $self->{_gateway} = $gateway;
        unless ($gateway->before_ssh_connect) {
            $self->_set_error(OSSH_MASTER_FAILED, 'Gateway setup failed', join(', ', $gateway->errors));
            return;
        }
        $proxy_command = $gateway->proxy_command;
    }

    if (defined $proxy_command) {
        push @master_opts, -o => "ProxyCommand=$proxy_command";
    }

    if ($use_pty) {
        _load_module('IO::Pty');
        $self->{_mpty} = $mpty = IO::Pty->new;
    }

    push @master_opts, -o => "PreferredAuthentications=$pref_auths"
        if defined $pref_auths;

    my @call = $self->_make_ssh_call(\@master_opts);

    local $SIG{CHLD};
    my $pid = fork;
    unless (defined $pid) {
        $self->_set_error(OSSH_MASTER_FAILED, "unable to fork ssh master: $!");
        return undef;
    }
    unless ($pid) {
        if ($debug and $debug & 512) {
            require Net::OpenSSH::OSTracer;
            Net::OpenSSH::OSTracer->trace;
        }

        $mpty->make_slave_controlling_terminal if $mpty;

	$self->_master_redirect('STDOUT');
	$self->_master_redirect('STDERR');

        delete $ENV{SSH_ASKPASS} if defined $self->{_passwd};
        delete $ENV{SSH_AUTH_SOCK} if defined $self->{_passphrase};

	local $SIG{__DIE__};
        eval { exec @call };
        POSIX::_exit(255);
    }
    $self->{_pid} = $pid;
    my $r = $self->_wait_for_master($async, 1);
    $mpty->close_slave if $mpty;
    $r;
}

sub _waitpid {
    my ($self, $pid, $timeout) = @_;
    $? = 0;
    if ($pid) {
        $timeout = $self->{_timeout} unless defined $timeout;

        my $time_limit;
        if (defined $timeout and $self->{_kill_ssh_on_timeout}) {
            $timeout = 0 if $self->error == OSSH_SLAVE_TIMEOUT;
            $time_limit = time + $timeout;
        }
        local $SIG{CHLD} = sub {};
	while (1) {
            my $r;
            if (defined $time_limit) {
                while (1) {
                    # TODO: we assume that all OSs return 0 when the
                    # process is still running, that may not be true!
                    $r = waitpid($pid, WNOHANG) and last;
                    my $remaining = $time_limit - time;
                    if ($remaining <= 0) {
                        $debug and $debug & 16 and _debug "killing SSH slave, pid: $pid";
                        kill TERM => $pid;
                        $self->_or_set_error(OSSH_SLAVE_TIMEOUT, "ssh slave failed", "timed out");
                    }
                    # There is a race condition here. We try to
                    # minimize it keeping the waitpid and the select
                    # together and limiting the sleep time to 1s:
                    my $sleep = ($remaining < 0.1 ? 0.1 : 1);
                    $debug and $debug & 16 and
                        _debug "waiting for slave, timeout: $timeout, remaining: $remaining, sleep: $sleep";
                    $r = waitpid($pid, WNOHANG) and last;
                    select(undef, undef, undef, $sleep);
                }
            }
            else {
                $r = waitpid($pid, 0);
            }
            $debug and $debug & 16 and _debug "_waitpid($pid) => pid: $r, rc: $!";
	    if ($r == $pid) {
		if ($?) {
		    my $signal = ($? & 255);
		    my $errstr = "child exited with code " . ($? >> 8);
		    $errstr .= ", signal $signal" if $signal;
		    $self->_or_set_error(OSSH_SLAVE_CMD_FAILED, $errstr);
		    return undef;
		}
		return 1;
	    }
	    if ($r > 0) {
		warn "internal error: spurious process $r exited";
		next;
	    }
	    next if $! == Errno::EINTR();
	    if ($! == Errno::ECHILD) {
		$self->_or_set_error(OSSH_SLAVE_FAILED, "child process $pid does not exist", $!);
		return undef
	    }
	    warn "Internal error: unexpected error (".($!+0).": $!) from waitpid($pid) = $r. Report it, please!";

	    # wait a bit before trying again
	    select(undef, undef, undef, 0.1);
	}
    }
    else {
	$self->_or_set_error(OSSH_SLAVE_FAILED, "spawning of new process failed");
	return undef;
    }
}

sub wait_for_master {
    my $self = shift;
    @_ <= 1 or croak 'Usage: $ssh->wait_for_master([$async])';
    return undef if $self->{_error} == OSSH_MASTER_FAILED;
    $self->{_error} = 0;
    return $self->_wait_for_master($_[0]) if $self->{_wfm_state};

    unless (-S $self->{_ctl_path}) {
	$self->_set_error(OSSH_MASTER_FAILED, "master ssh connection broken");
	return undef;
    }
    1;
}

sub check_master {
    my $self = shift;
    @_ and croak 'Usage: $ssh->check_master()';
    $self->{_error} = 0;
    $self->_wait_for_master;
}

sub _wait_for_master {
    my ($self, $async, $reset) = @_;

    my $state = delete $self->{_wfm_state} || 'waiting_for_mux_socket';
    my $bout = \ ($self->{_wfm_bout});

    my $mpty = $self->{_mpty};
    my $passwd = $deobfuscate->($self->{_passwd});
    my $login_handler = $self->{_login_handler};
    my $pid = $self->{_pid};
    # an undefined pid indicates we are reusing a master connection

    if ($reset) {
        $$bout = '';
        $state = ( (defined $passwd and $pid) ? 'waiting_for_password_prompt' :
                    (defined $login_handler)   ? 'waiting_for_login_handler'  :
                                                 'waiting_for_mux_socket' );
    }

    my $ctl_path = $self->{_ctl_path};
    my $dt = ($async ? 0 : 0.1);
    my $timeout = $self->{_timeout};
    my $start_time = time;

    my $fnopty;
    my $rv = '';
    if ($state eq 'waiting_for_password_prompt') {
        $fnopty = fileno $mpty;
        vec($rv, $fnopty, 1) = 1
    }

    local $self->{_error_prefix} = [@{$self->{_error_prefix}},
				    "unable to establish master SSH connection"];
    while (1) {
        last if (defined $timeout and (time - $start_time) > $timeout);

        if (-e $ctl_path) {
            $debug and $debug & 4 and _debug "file object found at $ctl_path";
            unless (-S $ctl_path) {
                $self->_set_error(OSSH_MASTER_FAILED,
                                  "bad ssh master at $ctl_path, object is not a socket");
                $self->_kill_master;
                return undef;
            }
            my $check = $self->_master_ctl('check');
            if (defined $check) {
                my $error;
		if ($check =~ /pid=(\d+)/) {
		    return 1 if (!$pid or $1 == $pid);
		    $error = "bad ssh master at $ctl_path, socket owned by pid $1 (pid $pid expected)";
		}
		elsif ($check =~ /illegal option/i) {
		    $error = "OpenSSH 4.1 or later required";
		}
		else {
		    $error = "Unknown error";
		}
                $self->_or_set_error(OSSH_MASTER_FAILED, $error);
            }
	    $self->_kill_master;
            return undef;
        }
        $debug and $debug & 4 and _debug "file object not yet found at $ctl_path";

        if ($self->{_perl_pid} != $$ or $self->{_thread_generation} != $thread_generation) {
            $self->_set_error(OSSH_MASTER_FAILED,
                              "process was forked or threaded before SSH connection had been established");
            return undef;
        }
        if (!$pid) {
            $self->_set_error(OSSH_MASTER_FAILED,
                              "socket does not exist");
            return undef;
        }
        elsif (waitpid($pid, WNOHANG) == $pid or $! == Errno::ECHILD) {
            my $error = "master process exited unexpectedly";
            $error =  "bad pass" . ($self->{_passphrase} ? 'phrase' : 'word') . " or $error"
                if defined $self->{_passwd};
            $self->_set_error(OSSH_MASTER_FAILED, $error);
            return undef;
        }
        if ($state eq 'waiting_for_login_handler') {
            local $SIG{__DIE__};
            local $@;
            if (eval { $login_handler->($self, $mpty, $bout) }) {
                $state = 'waiting_for_mux_socket';
                next;
            }
            if ($@) {
                $self->_set_error(OSSH_MASTER_FAILED,
                                  "custom login handler failed: $@");
                return undef;
            }
        }
        else {
            my $rv1 = $rv;
            my $n = select($rv1, undef, undef, $dt);
            if ($n > 0) {
                vec($rv1, $fnopty, 1)
                    or die "internal error";
                my $read = sysread($mpty, $$bout, 4096, length $$bout);
                if ($read) {
                    if ($state eq 'waiting_for_password_prompt') {
                        if ($$bout =~ /The authenticity of host.*can't be established/si) {
                            $self->_set_error(OSSH_MASTER_FAILED,
                                              "the authenticity of the target host can't be established, the remote host "
                                              . "public key is probably not present on the '~/.ssh/known_hosts' file");
                            $self->_kill_master;
                            return undef;
                        }
                        if ($$bout =~ s/^(.*:)//s) {
                            $debug and $debug & 4 and _debug "passwd/passphrase requested ($1)";
                            print $mpty "$passwd\n";
                            $state = 'waiting_for_mux_socket';
                        }
                    }
                    else { $$bout = '' }
                    next;
                }
            }
        }
        if ($async) {
            $self->{_wfm_state} = $state;
            return 0;
        }
        else {
            select(undef, undef, undef, $dt);
        }
    }
    $self->_set_error(OSSH_MASTER_FAILED, "login timeout");
    $self->_kill_master;
    undef;
}

sub _master_ctl {
    my ($self, $cmd) = @_;
    local $self->{_error_prefix} = [@{$self->{_error_prefix}},
                                    "control command failed"];
    $self->capture({ encoding => 'bytes', # don't let the encoding
					  # stuff go in the way
		     stdin_discard => 1, tty => 0,
                     stderr_to_stdout => 1, ssh_opts => [-O => $cmd]});
}

sub stop {
    # FIXME: this method currently fails because of a bug in ssh.
    my ($self, $timeout) = @_;
    my $pid = $self->{_pid};
    $self->_master_ctl('stop');
    if (not $self->error           and
        $pid                       and
        $self->{_perl_pid} == $$   and
        $self->{_thread_generation} == $thread_generation) {

        local $self->{_kill_ssh_on_timeout};
        if ($self->_waitpid($pid, $timeout)) {
            delete $self->{_pid};
            $self->_set_error(OSSH_MASTER_FAILED, "master ssh connection stopped");
            return 1;
        }
        else {
            return $self->_kill_master;
        }
    }
    undef;
}

sub _make_pipe {
    my $self = shift;
    my ($r, $w);
    if (pipe $r, $w) {
        my $old = select;
        select $r; $ |= 1;
        select $w; $ |= 1;
        select $old;
        return ($r, $w);
    }
    $self->_set_error(OSSH_SLAVE_PIPE_FAILED, "unable to create pipe: $!");
    return;
}

my %loaded_module;
sub _load_module {
    my ($module, $version) = @_;
    $loaded_module{$module} ||= do {
	do {
	    local $SIG{__DIE__};
	    local $@;
	    eval "require $module; 1"
	} or croak "unable to load Perl module $module";
        1
    };
    if (defined $version) {
	local $SIG{__DIE__};
	local $@;
	my $mv = eval "\$${module}::VERSION" || 0;
	(my $mv1 = $mv) =~ s/_\d*$//;
	croak "$module version $version required, $mv is available"
	    if $mv1 < $version;
    }
    1
}

my $noquote_class = '.\\w/\\-@,:';
my $glob_class    = '*?\\[\\],{}:!^~';

sub _arg_quoter {
    sub {
        my $quoted = join '',
            map { ( m|^'$|                  ? "\\'"  :
                    m|^[$noquote_class]*$|o ? $_     :
                                              "'$_'" ) } split /(')/, $_[0];
        length $quoted ? $quoted : "''";
    }
}

sub _arg_quoter_glob {
    sub {
	my $arg = shift;
        my @parts;
        while ((pos $arg ||0) < length $arg) {
            if ($arg =~ m|\G'|gc) {
                push @parts, "\\'";
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

	# my $arg = shift;
        # return $arg if $arg =~ m|^[\w/\-+=?\[\],{}\@!.^~]+$|;
	# return "''" if $arg eq '';
        # $arg =~ s|(?<!\\)([^\w/\-+=*?\[\],{}:\@!.^\\~])|ord($1) > 127 ? $1 : $1 eq "\n" ? "'\n'" : "\\$1"|ge;
	# $arg;
    }
}

sub _quote_args {
    my $self = shift;
    my $opts = shift;
    ref $opts eq 'HASH' or die "internal error";
    my $quote = delete $opts->{quote_args};
    my $quote_extended = delete $opts->{quote_args_extended};
    my $glob_quoting = delete $opts->{glob_quoting};
    $quote = (@_ > 1) unless defined $quote;

    if ($quote) {
	my $quoter_glob = $self->_arg_quoter_glob;
	my $quoter = ($glob_quoting
		      ? $quoter_glob
		      : $self->_arg_quoter);

	# foo   => $quoter
	# \foo  => $quoter_glob
	# \\foo => no quoting at all and disable extended quoting as it is not safe
	my @quoted;
	for (@_) {
	    if (ref $_) {
		if (ref $_ eq 'SCALAR') {
		    push @quoted, $quoter_glob->($self->_expand_vars($$_));
		}
		elsif (ref $_ eq 'REF' and ref $$_ eq 'SCALAR') {
		    push @quoted, $self->_expand_vars($$$_);
		    undef $quote_extended;
		}
		else {
		    croak "invalid reference in remote command argument list"
		}
	    }
	    else {
		push @quoted, $quoter->($self->_expand_vars($_));
	    }
	}

	if ($quote_extended) {
	    push @quoted, '</dev/null' if $opts->{stdin_discard};
	    if ($opts->{stdout_discard}) {
		push @quoted, '>/dev/null';
		push @quoted, '2>&1' if ($opts->{stderr_to_stdout} || $opts->{stderr_discard})
	    }
	    else {
		push @quoted, '2>/dev/null' if $opts->{stderr_discard};
	    }
	}
	wantarray ? @quoted : join(" ", @quoted);
    }
    else {
	croak "reference found in argument list when argument quoting is disabled"
	    if (grep ref, @_);

	my @args = $self->_expand_vars(@_);
	wantarray ? @args : join(" ", @args);
    }
}

sub shell_quote {
    shift->_quote_args({quote_args => 1}, @_);
}

sub shell_quote_glob {
    shift->_quote_args({quote_args => 1, glob_quoting => 1}, @_);
}

sub _array_or_scalar_to_list { map { defined($_) ? (ref $_ eq 'ARRAY' ? @$_ : $_ ) : () } @_ }

sub make_remote_command {
    my $self = shift;
    $self->wait_for_master or return;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my @ssh_opts = _array_or_scalar_to_list delete $opts{ssh_opts};
    my $tty = delete $opts{tty};
    push @ssh_opts, ($tty ? '-qtt' : '-T') if defined $tty;
    if ($self->{_forward_agent}) {
        my $forward_agent = delete $opts{forward_agent};
        push @ssh_opts, ($forward_agent ? '-A' : '-a') if defined $forward_agent;
    }
    my $tunnel = delete $opts{tunnel};
    my (@args);
    if ($tunnel) {
        @_ == 2 or croak "two arguments are required for tunnel command";
        push @ssh_opts, "-W" . join(":", @_);
    }
    else {
        @args = $self->_quote_args(\%opts, @_);
    }
    _croak_bad_options %opts;

    my @call = $self->_make_ssh_call(\@ssh_opts, @args);
    if (wantarray) {
	$debug and $debug & 16 and _debug_dump make_remote_command => \@call;
	return @call;
    }
    else {
	my $call = join ' ', $self->shell_quote(@call);
	$debug and $debug & 16 and _debug_dump 'make_remote_command (quoted)' => $call;
	return $call
    }
}

sub _open_file {
    my ($self, $default_mode, $name_or_args) = @_;
    my ($mode, @args) = (ref $name_or_args
			 ? @$name_or_args
			 : ($default_mode, $name_or_args));
    @args = $self->_expand_vars(@args);
    if (open my $fh, $mode, @args) {
	return $fh;
    }
    else {
	$self->_set_error(OSSH_SLAVE_PIPE_FAILED,
			  "Unable to open file '$args[0]': $!");
	return undef;
    }
}

sub _fileno_dup_over {
    my ($good_fn, $fh) = @_;
    if (defined $fh) {
        my @keep_open;
        my $fn = fileno $fh;
        for (1..5) {
            $fn >= $good_fn and return $fn;
            $fn = POSIX::dup($fn);
            push @keep_open, $fn;
        }
        POSIX::_exit(255);
    }
    undef;
}

sub _exec_dpipe {
    my ($self, $cmd, $io, $err) = @_;
    my $io_fd  = _fileno_dup_over(3 => $io);
    my $err_fd = _fileno_dup_over(3 => $err);
    POSIX::dup2($io_fd, 0);
    POSIX::dup2($io_fd, 1);
    POSIX::dup2($err_fd, 2) if defined $err_fd;
    if (ref $cmd) {
        exec @$cmd;
    }
    else {
        exec $cmd;
    }
}

sub _delete_stream_encoding {
    my ($self, $opts) = @_;
    _first_defined(delete $opts->{stream_encoding},
                   $opts->{encoding},
                   $self->{_default_stream_encoding});
}

sub _delete_argument_encoding {
    my ($self, $opts) = @_;
    _first_defined(delete $opts->{argument_encoding},
                   delete $opts->{encoding},
                   $self->{_default_argument_encoding});
}

sub open_ex {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    $self->wait_for_master or return;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $tunnel = delete $opts{tunnel};
    my ($stdinout_socket, $stdinout_dpipe_make_parent);
    my $stdinout_dpipe = delete $opts{stdinout_dpipe};
    if ($stdinout_dpipe) {
        $stdinout_dpipe_make_parent = delete $opts{stdinout_dpipe_make_parent};
        $stdinout_socket = 1;
    }
    else {
        $stdinout_socket = delete $opts{stdinout_socket};
    }

    my ($stdin_discard, $stdin_pipe, $stdin_fh, $stdin_file, $stdin_pty,
        $stdout_discard, $stdout_pipe, $stdout_fh, $stdout_file, $stdout_pty,
        $stderr_discard, $stderr_pipe, $stderr_fh, $stderr_file, $stderr_to_stdout);
    unless ($stdinout_socket) {
        ( $stdin_discard = delete $opts{stdin_discard} or
          $stdin_pipe = delete $opts{stdin_pipe} or
          $stdin_fh = delete $opts{stdin_fh} or
          $stdin_file = delete $opts{stdin_file} or
          (not $tunnel and $stdin_pty = delete $opts{stdin_pty}) );

        ( $stdout_discard = delete $opts{stdout_discard} or
          $stdout_pipe = delete $opts{stdout_pipe} or
          $stdout_fh = delete $opts{stdout_fh} or
          $stdout_file = delete $opts{stdout_file} or
          (not $tunnel and $stdout_pty = delete $opts{stdout_pty}) );

        $stdout_pty and !$stdin_pty
            and croak "option stdout_pty requires stdin_pty set";
    }

    ( $stderr_discard = delete $opts{stderr_discard} or
      $stderr_pipe = delete $opts{stderr_pipe} or
      $stderr_fh = delete $opts{stderr_fh} or
      $stderr_to_stdout = delete $opts{stderr_to_stdout} or
      $stderr_file = delete $opts{stderr_file} );

    my $argument_encoding = $self->_delete_argument_encoding(\%opts);
    my $ssh_opts = delete $opts{ssh_opts};
    $ssh_opts = $self->{_default_ssh_opts} unless defined $ssh_opts;
    my @ssh_opts = $self->_expand_vars(_array_or_scalar_to_list $ssh_opts);

    if ($self->{_forward_agent}) {
        my $forward_agent = delete $opts{forward_agent};
        push @ssh_opts, ($forward_agent ? '-A' : '-a') if defined $forward_agent;
    }

    my ($cmd, $close_slave_pty, @args);
    if ($tunnel) {
	@_ == 2 or croak 'bad number of arguments for tunnel, use $ssh->method(\\%opts, $host, $port)';
	@args = @_;
    }
    else {
	if ($stdin_pty) {
	    $close_slave_pty = delete $opts{close_slave_pty};
	    $close_slave_pty = 1 unless defined $close_slave_pty;
	}

	my $tty = delete $opts{tty};
	push @ssh_opts, ($tty ? '-qtt' : '-T') if defined $tty;

	$cmd = delete $opts{_cmd} || 'ssh';
	$opts{quote_args_extended} = 1
	    if (not defined $opts{quote_args_extended} and $cmd eq 'ssh');
        @args = $self->_quote_args(\%opts, @_);
        $self->_encode_args($argument_encoding, @args) or return;
    }

    _croak_bad_options %opts;

    if (defined $stdin_file) {
	$stdin_fh = $self->_open_file('<', $stdin_file) or return
    }
    if (defined $stdout_file) {
	$stdout_fh = $self->_open_file('>', $stdout_file) or return
    }
    if (defined $stderr_file) {
	$stderr_fh = $self->_open_file('>', $stderr_file) or return
    }

    my ($rin, $win, $rout, $wout, $rerr, $werr);

    if ($stdinout_socket) {
        unless(socketpair $rin, $win, AF_UNIX, SOCK_STREAM, PF_UNSPEC) {
            $self->_set_error(OSSH_SLAVE_PIPE_FAILED, "socketpair failed: $!");
            return;
        }
        $wout = $rin;
    }
    else {
        if ($stdin_pipe) {
            ($rin, $win) = $self->_make_pipe or return;
        }
        elsif ($stdin_pty) {
            _load_module('IO::Pty');
            $win = IO::Pty->new;
            unless ($win) {
                $self->_set_error(OSSH_SLAVE_PIPE_FAILED, "unable to allocate pseudo-tty: $!");
                return;
            }
            $rin = $win->slave;
        }
        elsif (defined $stdin_fh) {
            $rin = $stdin_fh;
        }
        else {
            $rin = $self->{_default_stdin_fh}
        }
        _check_is_system_fh STDIN => $rin;

        if ($stdout_pipe) {
            ($rout, $wout) = $self->_make_pipe or return;
        }
        elsif ($stdout_pty) {
            $wout = $rin;
        }
        elsif (defined $stdout_fh) {
            $wout = $stdout_fh;
        }
        else {
            $wout = $self->{_default_stdout_fh};
        }
        _check_is_system_fh STDOUT => $wout;
    }

    unless ($stderr_to_stdout) {
	if ($stderr_pipe) {
	    ($rerr, $werr) = $self->_make_pipe or return;
	}
	elsif (defined $stderr_fh) {
	    $werr = $stderr_fh;
	}
	else {
	    $werr = $self->{_default_stderr_fh};
	}
	_check_is_system_fh STDERR => $werr;
    }

    my @call = ( $tunnel         ? $self->_make_tunnel_call(\@ssh_opts, @args) :
                 $cmd eq 'ssh'   ? $self->_make_ssh_call(\@ssh_opts, @args)    :
		 $cmd eq 'scp'   ? $self->_make_scp_call(\@ssh_opts, @args)    :
		 $cmd eq 'rsync' ? $self->_make_rsync_call(\@ssh_opts, @args)  :
		 die "internal error: bad _cmd protocol" );

    $debug and $debug & 16 and _debug_dump open_ex => \@call;

    my $pid = fork;
    unless ($pid) {
        unless (defined $pid) {
            $self->_set_error(OSSH_SLAVE_FAILED,
                              "unable to fork new ssh slave: $!");
            return;
        }

        $stdin_discard  and (open $rin,  '<', '/dev/null' or POSIX::_exit(255));
        $stdout_discard and (open $wout, '>', '/dev/null' or POSIX::_exit(255));
        $stderr_discard and (open $werr, '>', '/dev/null' or POSIX::_exit(255));

        if ($stdinout_dpipe) {
            my $pid1 = fork;
            defined $pid1 or POSIX::_exit(255);

            unless ($pid1 xor $stdinout_dpipe_make_parent) {
                eval { $self->_exec_dpipe($stdinout_dpipe, $win, $werr) };
                POSIX::_exit(255);
            }
        }

        my $rin_fd  = _fileno_dup_over(0 => $rin);
        my $wout_fd = _fileno_dup_over(1 => $wout);
        my $werr_fd = _fileno_dup_over(2 => $werr);

        if (defined $rin_fd) {
            $win->make_slave_controlling_terminal if $stdin_pty;
	    $rin_fd == 0 or POSIX::dup2($rin_fd, 0) or POSIX::_exit(255);
        }
	if (defined $wout_fd) {
            $wout_fd == 1 or POSIX::dup2($wout_fd, 1) or POSIX::_exit(255);
        }
        if (defined $werr_fd) {
            $werr_fd == 2 or POSIX::dup2($werr_fd, 2) or POSIX::_exit(255);
        }
        elsif ($stderr_to_stdout) {
            POSIX::dup2(1, 2) or POSIX::_exit(255);
        }
        do { exec @call };
        POSIX::_exit(255);
    }
    $win->close_slave() if $close_slave_pty;
    undef $win if defined $stdinout_dpipe;
    wantarray ? ($win, $rout, $rerr, $pid) : $pid;
}

sub pipe_in {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    $self->wait_for_master or return;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $argument_encoding = $self->_delete_argument_encoding(\%opts);
    my @args = $self->_quote_args(\%opts, @_);
    _croak_bad_options %opts;

    $self->_encode_args($argument_encoding, @args) or return;
    my @call = $self->_make_ssh_call([], @args);
    $debug and $debug & 16 and _debug_dump pipe_in => @call;
    my $pid = open my $rin, '|-', @call;
    unless ($pid) {
        $self->_set_error(OSSH_SLAVE_FAILED,
                          "unable to fork new ssh slave: $!");
        return;
    }
    return wantarray ? ($rin, $pid) : $rin;
}

sub pipe_out {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    $self->wait_for_master or return;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $argument_encoding = $self->_delete_argument_encoding(\%opts);
    my @args = $self->_quote_args(\%opts, @_);
    _croak_bad_options %opts;

    $self->_encode_args($argument_encoding, @args) or return;
    my @call = $self->_make_ssh_call([], @args);
    $debug and $debug & 16 and _debug_dump pipe_out => @call;
    my $pid = open my $rout, '-|', @call;
    unless ($pid) {
        $self->_set_error(OSSH_SLAVE_FAILED,
                          "unable to fork new ssh slave: $!");
        return;
    }
    return wantarray ? ($rout, $pid) : $rout;
}

sub _find_encoding {
    my ($self, $encoding, $data) = @_;
    if (defined $encoding and $encoding ne 'bytes') {
	_load_module('Encode');
        my $enc = Encode::find_encoding($encoding);
        unless (defined $enc) {
            $self->_set_error(OSSH_ENCODING_ERROR, "bad encoding '$encoding'");
            return
        }
        return $enc
    }
    return undef
}

sub _encode {
    my $self = shift;
    my $enc = shift;
    if (defined $enc and @_) {
        local $@;
        eval {
            for (@_) {
                defined or next;
                $_ = $enc->encode($_, Encode::FB_CROAK());
            }
        };
        $self->_check_eval_ok(OSSH_ENCODING_ERROR) or return undef;
    }
    1;
}

sub _encode_args {
    if (@_ > 2) {
        my $self = shift;
        my $encoding = shift;

        my $enc = $self->_find_encoding($encoding);
        if ($enc) {
            local $self->{_error_prefix} = [@{$self->{_error_prefix}}, "argument encoding failed"];
            $self->_encode($enc, @_);
        }
        return !$self->error;
    }
    1;
}

sub _decode {
    my $self = shift;
    my $enc = shift;
    local $@;
    eval {
        for (@_) {
            defined or next;
            $_ = $enc->decode($_, Encode::FB_CROAK());
        }
    };
    $self->_check_eval_ok(OSSH_ENCODING_ERROR);
}

sub _io3 {
    my ($self, $out, $err, $in, $stdin_data, $timeout, $encoding) = @_;
    $self->wait_for_master or return;
    my @data = _array_or_scalar_to_list $stdin_data;
    my ($cout, $cerr, $cin) = (defined($out), defined($err), defined($in));
    $timeout = $self->{_timeout} unless defined $timeout;

    my $has_input = grep { defined and length } @data;
    if ($cin and !$has_input) {
        close $in;
        undef $cin;
    }
    elsif (!$cin and $has_input) {
        croak "remote input channel is not defined but data is available for sending"
    }

    my $enc = $self->_find_encoding($encoding);
    if ($enc and @data) {
        local $self->{_error_prefix} = [@{$self->{_error_prefix}}, "stdin data encoding failed"];
        $self->_encode($enc, @data) if $has_input;
        return if $self->error;
    }

    my $bout = '';
    my $berr = '';
    my ($fnoout, $fnoerr, $fnoin);
    local $SIG{PIPE} = 'IGNORE';

 MLOOP: while ($cout or $cerr or $cin) {
        $debug and $debug & 64 and _debug "io3 mloop, cin: " . ($cin || 0) .
            ", cout: " . ($cout || 0) . ", cerr: " . ($cerr || 0);
        my ($rv, $wv);

        if ($cout or $cerr) {
            $rv = '';
            if ($cout) {
                $fnoout = fileno $out;
                vec($rv, $fnoout, 1) = 1;
            }
            if ($cerr) {
                $fnoerr = fileno $err;
                vec($rv, $fnoerr, 1) = 1
            }
        }

        if ($cin) {
            $fnoin = fileno $in;
            $wv = '';
            vec($wv, $fnoin, 1) = 1;
        }

        my $recalc_vecs;
    FAST: until ($recalc_vecs) {
            $debug and $debug & 64 and
                _debug "io3 fast, cin: " . ($cin || 0) .
                    ", cout: " . ($cout || 0) . ", cerr: " . ($cerr || 0);
            my ($rv1, $wv1) = ($rv, $wv);
            my $n = select ($rv1, $wv1, undef, $timeout);
            if ($n > 0) {
                if ($cout and vec($rv1, $fnoout, 1)) {
                    my $offset = length $bout;
                    my $read = sysread($out, $bout, 20480, $offset);
                    if ($debug and $debug & 64) {
                        _debug "stdout, bytes read: ", $read, " at offset $offset";
                        $read and $debug & 128 and _hexdump substr $bout, $offset;
                    }
                    unless ($read) {
                        close $out;
                        undef $cout;
                        $recalc_vecs = 1;
                        last unless $rv =~ /[^\x00]/;
                    }
                }
                if ($cerr and vec($rv1, $fnoerr, 1)) {
                    my $read = sysread($err, $berr, 20480, length($berr));
                    $debug and $debug & 64 and _debug "stderr, bytes read: ", $read;
                    unless ($read) {
                        close $err;
                        undef $cerr;
                        $recalc_vecs = 1;
                    }
                }
                if ($cin and vec($wv1, $fnoin, 1)) {
                    my $written = syswrite($in, $data[0], 20480);
                    if ($debug and $debug & 64) {
                        _debug "stdin, bytes written: ", $written;
                        $written and $debug & 128 and _hexdump substr $data[0], 0, $written;
                    }
                    if ($written) {
                        substr($data[0], 0, $written, '');
                        while (@data) {
                            next FAST
                                if (defined $data[0] and length $data[0]);
                            shift @data;
                        }
                    }
                    close $in;
                    undef $cin;
                    $recalc_vecs = 1;
                }
            }
            else {
                next if ($n < 0 and $! == Errno::EINTR());
                $self->_set_error(OSSH_SLAVE_TIMEOUT, 'ssh slave failed', 'timed out');
                last MLOOP;
            }
        }
    }
    close $out if $cout;
    close $err if $cerr;
    close $in if $cin;

    if ($enc) {
        local $self->{_error_prefix} = [@{$self->{_error_prefix}}, 'output decoding failed'];
        unless ($self->_decode($enc, $bout, $berr)) {
            undef $bout;
            undef $berr;
        }
    }
    $debug and $debug & 64 and _debug "leaving _io3()";
    return ($bout, $berr);
}



_sub_options spawn => qw(stderr_to_stdout stdin_discard stdin_fh stdin_file stdout_discard
                         stdout_fh stdout_file stderr_discard stderr_fh stderr_file
                         stdinout_dpipe stdinout_dpipe_make_parent quote_args tty ssh_opts tunnel
                         encoding argument_encoding forward_agent);
sub spawn {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts =  (ref $_[0] eq 'HASH' ? %{shift()} : ());
    _croak_bad_options %opts;

    return scalar $self->open_ex(\%opts, @_);
}

_sub_options open2 => qw(stderr_to_stdout stderr_discard stderr_fh stderr_file quote_args
                         tty ssh_opts tunnel encoding argument_encoding forward_agent);
sub open2 {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    _croak_bad_options %opts;

    my ($in, $out, undef, $pid) =
        $self->open_ex({ stdout_pipe => 1,
                         stdin_pipe => 1,
                         %opts }, @_) or return ();
    return ($in, $out, $pid);
}

_sub_options open2pty => qw(stderr_to_stdout stderr_discard stderr_fh stderr_file quote_args tty
                            close_slave_pty ssh_opts encoding argument_encoding forward_agent);
sub open2pty {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    _croak_bad_options %opts;

    my ($pty, undef, undef, $pid) =
        $self->open_ex({ stdout_pty => 1,
                         stdin_pty => 1,
			 tty => 1,
                       %opts }, @_) or return ();
    return ($pty, $pid);
}

_sub_options open2socket => qw(stderr_to_stdout stderr_discard stderr_fh stderr_file quote_args tty
                               ssh_opts tunnel encoding argument_encoding forward_agent);
sub open2socket {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    _croak_bad_options %opts;

    my ($socket, undef, undef, $pid) =
        $self->open_ex({ stdinout_socket => 1,
                         %opts }, @_) or return ();
    return ($socket, $pid);
}

_sub_options open3 => qw(quote_args tty ssh_opts encoding argument_encoding forward_agent);
sub open3 {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    _croak_bad_options %opts;

    my ($in, $out, $err, $pid) =
        $self->open_ex({ stdout_pipe => 1,
                         stdin_pipe => 1,
                         stderr_pipe => 1,
			 %opts },
                       @_) or return ();
    return ($in, $out, $err, $pid);
}

_sub_options open3pty => qw(quote_args tty close_slave_pty ssh_opts
                            encoding argument_encoding forward_agent);
sub open3pty {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    _croak_bad_options %opts;

    my ($pty, undef, $err, $pid) =
        $self->open_ex({ stdout_pty => 1,
                         stdin_pty => 1,
			 tty => 1,
                         stderr_pipe => 1,
			 %opts },
                       @_) or return ();
    return ($pty, $err, $pid);
}

_sub_options system => qw(stdout_discard stdout_fh stdin_discard stdout_file stdin_fh stdin_file
                          quote_args stderr_to_stdout stderr_discard stderr_fh stderr_file
                          stdinout_dpipe stdinout_dpipe_make_parent tty ssh_opts tunnel encoding
                          argument_encoding forward_agent);
sub system {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $stdin_data = delete $opts{stdin_data};
    my $timeout = delete $opts{timeout};
    my $async = delete $opts{async};
    _croak_bad_options %opts;

    local $SIG{INT} = 'IGNORE';
    local $SIG{QUIT} = 'IGNORE';
    local $SIG{CHLD};

    my $stream_encoding;
    if (defined $stdin_data) {
        $opts{stdin_pipe} = 1;
        $stream_encoding = $self->_delete_stream_encoding(\%opts);
    }
    my ($in, undef, undef, $pid) = $self->open_ex(\%opts, @_) or return undef;

    $self->_io3(undef, undef, $in, $stdin_data, $timeout, $stream_encoding) if defined $stdin_data;
    return $pid if $async;
    $self->_waitpid($pid, $timeout);
}

_sub_options test => qw(stdout_discard stdout_fh stdin_discard stdout_file stdin_fh stdin_file
                        quote_args stderr_to_stdout stderr_discard stderr_fh stderr_file
                        stdinout_dpipe stdinout_dpipe_make_parent tty ssh_opts timeout stdin_data
                        encoding stream_encoding argument_encoding forward_agent);
sub test {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    $opts{stdout_discard} = 1 unless grep defined($opts{$_}), qw(stdout_discard stdout_fh
                                                                 stdout_file stdinout_dpipe);
    $opts{stderr_discard} = 1 unless grep defined($opts{$_}), qw(stderr_discard stderr_fh
                                                                 stderr_file stderr_to_stdout);
    _croak_bad_options %opts;

    $self->system(\%opts, @_);
    my $error = $self->error;
    unless ($error) {
        return 1;
    }
    if ($error == OSSH_SLAVE_CMD_FAILED) {
        $self->_set_error(0);
        return 0;
    }
    return undef;
}

_sub_options capture => qw(stderr_to_stdout stderr_discard stderr_fh stderr_file
                           stdin_discard stdin_fh stdin_file quote_args tty ssh_opts tunnel
                           encoding argument_encoding forward_agent);
sub capture {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $stdin_data = delete $opts{stdin_data};
    my $timeout = delete $opts{timeout};
    _croak_bad_options %opts;

    my $stream_encoding = $self->_delete_stream_encoding(\%opts);
    $opts{stdout_pipe} = 1;
    $opts{stdin_pipe} = 1 if defined $stdin_data;

    local $SIG{INT} = 'IGNORE';
    local $SIG{QUIT} = 'IGNORE';
    local $SIG{CHLD};

    my ($in, $out, undef, $pid) = $self->open_ex(\%opts, @_) or return ();
    my ($output) = $self->_io3($out, undef, $in, $stdin_data, $timeout, $stream_encoding);
    $self->_waitpid($pid, $timeout);
    if (wantarray) {
        my $pattern = quotemeta $/;
        return split /(?<=$pattern)/, $output;
    }
    $output
}

_sub_options capture2 => qw(stdin_discard stdin_fh stdin_file
                            quote_args tty ssh_opts encoding
                            argument_encoding forward_agent);
sub capture2 {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $stdin_data = delete $opts{stdin_data};
    my $timeout = delete $opts{timeout};
    _croak_bad_options %opts;

    my $stream_encoding = $self->_delete_stream_encoding(\%opts);
    $opts{stdout_pipe} = 1;
    $opts{stderr_pipe} = 1;
    $opts{stdin_pipe} = 1 if defined $stdin_data;

    local $SIG{INT} = 'IGNORE';
    local $SIG{QUIT} = 'IGNORE';
    local $SIG{CHLD};

    my ($in, $out, $err, $pid) = $self->open_ex( \%opts, @_) or return ();
    my @capture = $self->_io3($out, $err, $in, $stdin_data, $timeout, $stream_encoding);
    $self->_waitpid($pid, $timeout);
    wantarray ? @capture : $capture[0];
}

_sub_options open_tunnel => qw(ssh_opts stderr_discard stderr_fh stderr_file encoding argument_encoding forward_agent);
sub open_tunnel {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    $opts{stderr_discard} = 1 unless grep defined $opts{$_}, qw(stderr_discard stderr_fh stderr_file);
    _croak_bad_options %opts;
    @_ == 2 or croak 'Usage: $ssh->open_tunnel(\%opts, $host, $port)';
    $opts{tunnel} = 1;
    $self->open2socket(\%opts, @_);
}

_sub_options capture_tunnel => qw(ssh_opts stderr_discard stderr_fh stderr_file stdin_discard
				  stdin_fh stdin_file stdin_data timeout encoding stream_encoding
				  argument_encoding forward_agent);
sub capture_tunnel {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    $opts{stderr_discard} = 1 unless grep defined $opts{$_}, qw(stderr_discard stderr_fh stderr_file);
    _croak_bad_options %opts;
    @_ == 2 or croak 'Usage: $ssh->capture_tunnel(\%opts, $host, $port)';
    $opts{tunnel} = 1;
    $self->capture(\%opts, @_);
}

sub _calling_method {
    my $method = (caller 2)[3];
    $method =~ s/.*:://;
    $method;
}

sub _scp_get_args {
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());

    @_ > 0 or croak
	'Usage: $ssh->' . _calling_method . '(\%opts, $remote_fn1, $remote_fn2, ..., $local_fn_or_dir)';

    my $glob = delete $opts{glob};

    my $target = (@_ > 1 ? pop @_ : '.');
    $target =~ m|^[^/]*:| and $target = "./$target";

    my $prefix = $self->{_host_squared};
    $prefix = "$self->{_user}\@$prefix" if defined $self->{_user};
    my @src = map "$prefix:$_", $self->_quote_args({quote_args => 1,
                                                    glob_quoting => $glob},
                                                   @_);
    ($self, \%opts, $target, @src);
}

sub scp_get {
    ${^TAINT} and &_catch_tainted_args;
    my ($self, $opts, $target, @src) = _scp_get_args @_;
    $self->_scp($opts, @src, $target);
}

sub rsync_get {
    ${^TAINT} and &_catch_tainted_args;
    my ($self, $opts, $target, @src) = _scp_get_args @_;
    $self->_rsync($opts, @src, $target);
}

sub _scp_put_args {
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());

    @_ > 0 or croak
	'Usage: $ssh->' . _calling_method . '(\%opts, $local_fn1, $local_fn2, ..., $remote_dir_or_fn)';

    my $glob = delete $opts{glob};
    my $glob_flags = ($glob ? delete $opts{glob_flags} || 0 : undef);

    my $prefix = $self->{_host_squared};
    $prefix = "$self->{_user}\@$prefix" if defined $self->{_user};

    my $target = $prefix . ':' . ( @_ > 1
                                   ? $self->_quote_args({quote_args => 1}, pop(@_))
                                   : '');

    my @src = @_;
    if ($glob) {
	require File::Glob;
	@src = map File::Glob::bsd_glob($_, $glob_flags), @src;
	unless (@src) {
	    $self->_set_error(OSSH_SLAVE_FAILED,
			      "given file name patterns did not match any file");
	    return undef;
	}
    }
    $_ = "./$_" for grep m|^[^/]*:|, @src;

    ($self, \%opts, $target, @src);
}

sub scp_put {
    ${^TAINT} and &_catch_tainted_args;
    my ($self, $opts, $target, @src) = _scp_put_args @_;
    $self->_scp($opts, @src, $target);
}

sub rsync_put {
    ${^TAINT} and &_catch_tainted_args;
    my ($self, $opts, $target, @src) = _scp_put_args @_;
    $self->_rsync($opts, @src, $target);
}

_sub_options _scp => qw(stderr_to_stdout stderr_discard stderr_fh
			stderr_file stdout_discard stdout_fh
			stdout_file encoding argument_encoding
                        forward_agent);
sub _scp {
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $quiet = delete $opts{quiet};
    $quiet = 1 unless defined $quiet;
    my $recursive = delete $opts{recursive};
    my $copy_attrs = delete $opts{copy_attrs};
    my $bwlimit = delete $opts{bwlimit};
    my $async = delete $opts{async};
    my $ssh_opts = delete $opts{ssh_opts};
    my $timeout = delete $opts{timeout};
    my $verbose = delete $opts{verbose};
    _croak_bad_options %opts;

    my @opts;
    @opts = @$ssh_opts if $ssh_opts;
    push @opts, '-q' if $quiet;
    push @opts, '-v' if $verbose;
    push @opts, '-r' if $recursive;
    push @opts, '-p' if $copy_attrs;
    push @opts, '-l', $bwlimit if defined $bwlimit;

    local $self->{_error_prefix} = [@{$self->{_error_prefix}}, 'scp failed'];

    my $pid = $self->open_ex({ %opts,
                               _cmd => 'scp',
			       ssh_opts => \@opts,
			       quote_args => 0 },
			     @_);

    return $pid if $async;
    $self->_waitpid($pid, $timeout);
}

my %rsync_opt_with_arg = map { $_ => 1 } qw(chmod suffix backup-dir rsync-path max-delete max-size min-size partial-dir
                                            timeout modify-window temp-dir compare-dest copy-dest link-dest compress-level
                                            skip-compress filter exclude exclude-from include include-from
                                            out-format log-file log-file-format bwlimit protocol iconv checksum-seed);

my %rsync_opt_forbiden = map { $_ => 1 } qw(rsh address port sockopts blocking-io password-file write-batch
                                            only-write-batch read-batch ipv4 ipv6 version help daemon config detach
                                            files-from from0 blocking-io protect-args list-only);

$rsync_opt_forbiden{"no-$_"} = 1 for (keys %rsync_opt_with_arg, keys %rsync_opt_forbiden);

my %rsync_error = (1, 'syntax or usage error',
		   2, 'protocol incompatibility',
		   3, 'errors selecting input/output files, dirs',
		   4, 'requested action not supported: an attempt was made to manipulate 64-bit files on a platform '.
                      'that  cannot  support them; or an option was specified that is supported by the client and not '.
                      'by the server.',
		   5, 'error starting client-server protocol',
		   6, 'daemon unable to append to log-file',
		   10, 'error in socket I/O',
		   11, 'error in file I/O',
		   12, 'error in rsync protocol data stream',
		   13, 'errors with program diagnostics',
		   14, 'error in IPC code',
		   20, 'received SIGUSR1 or SIGINT',
		   21, 'some error returned by waitpid()',
		   22, 'error allocating core memory buffers',
		   23, 'partial transfer due to error',
		   24, 'partial transfer due to vanished source files',
		   25, 'the --max-delete limit stopped deletions',
		   30, 'timeout in data send/receive',
		   35, 'timeout waiting for daemon connection');

my %rsync_opt_open_ex = map { $_ => 1 } qw(stderr_to_stdout
					   stderr_discard stderr_fh
					   stderr_file stdout_discard
					   stdout_fh stdout_file encoding
                                           argument_encoding);
sub _rsync {
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $async = delete $opts{async};
    my $verbose = delete $opts{verbose};
    my $quiet = delete $opts{quiet};
    my $copy_attrs = delete $opts{copy_attrs};
    my $timeout = delete $opts{timeout};
    $quiet = 1 unless (defined $quiet or $verbose);

    my @opts = qw(--blocking-io) ;
    push @opts, '-q' if $quiet;
    push @opts, '-p' if $copy_attrs;
    push @opts, '-' . ($verbose =~ /^\d+$/ ? 'v' x $verbose : 'v') if $verbose;

    my %opts_open_ex = ( _cmd => 'rsync',
			 quote_args => 0 );

    for my $opt (keys %opts) {
	my $value = $opts{$opt};
	if (defined $value) {
	    if ($rsync_opt_open_ex{$opt}) {
		$opts_open_ex{$opt} = $value;
	    }
	    else {
		my $opt1 = $opt;
		$opt1 =~ tr/_/-/;
		$rsync_opt_forbiden{$opt1} and croak "forbiden rsync option '$opt' used";
		if ($rsync_opt_with_arg{$opt1}) {
		    push @opts, "--$opt1=$_" for _array_or_scalar_to_list($value)
		}
		else {
		    $value = !$value if $opt1 =~ s/^no-//;
		    push @opts, ($value ? "--$opt1" : "--no-$opt1");
		}
	    }
	}
    }

    local $self->{_error_prefix} = [@{$self->{_error_prefix}}, 'rsync failed'];

    my $pid = $self->open_ex(\%opts_open_ex, @opts, '--', @_);
    return $pid if $async;
    $self->_waitpid($pid, $timeout) and return 1;

    if ($self->error == OSSH_SLAVE_CMD_FAILED and $?) {
	my $err = ($? >> 8);
	my $errstr = $rsync_error{$err};
	$errstr = 'Unknown rsync error' unless defined $errstr;
	my $signal = $? & 255;
	my $signalstr = ($signal ? " (signal $signal)" : '');
	$self->_set_error(OSSH_SLAVE_CMD_FAILED,
			  "command exited with code $err$signalstr: $errstr");
    }
    return undef
}

_sub_options sftp => qw(autoflush timeout argument_encoding encoding block_size
			queue_size late_set_perm forward_agent);

sub sftp {
    ${^TAINT} and &_catch_tainted_args;
    @_ & 1 or croak 'Usage: $ssh->sftp(%sftp_opts)';
    _load_module('Net::SFTP::Foreign', '1.47');
    my ($self, %opts) = @_;
    my $stderr_fh = delete $opts{stderr_fh};
    my $stderr_discard = delete $opts{stderr_discard};
    my $fs_encoding = _first_defined(delete $opts{fs_encoding},
                                     $opts{argument_encoding},
                                     $opts{encoding},
                                     $self->{_default_argument_encoding});
    undef $fs_encoding if (defined $fs_encoding and $fs_encoding eq 'bytes');
    _croak_bad_options %opts;
    $opts{timeout} = $self->{_timeout} unless defined $opts{timeout};
    $self->wait_for_master or return undef;
    my ($in, $out, $pid) = $self->open2( { ssh_opts => '-s',
					   stderr_fh => $stderr_fh,
					   stderr_discard => $stderr_discard },
					 'sftp' )
	or return undef;

    my $sftp = Net::SFTP::Foreign->new(transport => [$out, $in, $pid],
				       dirty_cleanup => 0,
                                       fs_encoding => $fs_encoding,
				       %opts);
    if ($sftp->error) {
	$self->_or_set_error(OSSH_SLAVE_SFTP_FAILED, "unable to create SFTP client", $sftp->error);
	return undef;
    }
    $sftp
}

_sub_options sshfs_import => qw(stderr_discard stderr_fh stderr_file
                                ssh_opts argument_encoding sshfs_opts);
sub sshfs_import {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    @_ == 2 or croak 'Usage: $ssh->sshfs_import(\%opts, $remote, $local)';
    my ($from, $to) = @_;
    my @sshfs_opts = ( -o => 'slave',
                       _array_or_scalar_to_list delete $opts{sshfs_opts} );
    _croak_bad_options %opts;

    $opts{ssh_opts} = ['-s', _array_or_scalar_to_list delete $opts{ssh_opts}];
    $opts{stdinout_dpipe} = [$self->{_sshfs_cmd}, "$self->{_host_squared}:$from", $to, @sshfs_opts];
    $opts{stdinout_dpipe_make_parent} = 1;
    $self->spawn(\%opts, 'sftp');
}

_sub_options sshfs_export => qw(stderr_discard stderr_fh stderr_file
                                ssh_opts argument_encoding sshfs_opts);
sub sshfs_export {
    ${^TAINT} and &_catch_tainted_args;
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    @_ == 2 or croak 'Usage: $ssh->sshfs_export(\%opts, $local, $remote)';
    my ($from, $to) = @_;
    my @sshfs_opts = ( -o => 'slave',
                       _array_or_scalar_to_list delete $opts{sshfs_opts} );
    _croak_bad_options %opts;
    $opts{stdinout_dpipe} = $self->{_sftp_server_cmd};

    my $hostname = eval {
        require Sys::Hostname;
        Sys::Hostname::hostname();
    };
    $hostname = 'remote' if (not defined $hostname   or
                             not length $hostname    or
                             $hostname=~/^localhost\b/);
    $self->spawn(\%opts, $self->{_sshfs_cmd}, "$hostname:$from", $to, @sshfs_opts);
}

sub DESTROY {
    my $self = shift;
    my $pid = $self->{_pid};
    local $@;
    $debug and $debug & 2 and _debug("DESTROY($self, pid: ", $pid, ")");
    if ($pid and $self->{_perl_pid} == $$ and $self->{_thread_generation} == $thread_generation) {
	$debug and $debug & 32 and _debug("killing master");
        local $?;
	local $!;

	unless ($self->{_wfm_state}) {
	    # we have successfully created the master connection so we
	    # can send control commands:
	    $debug and $debug & 32 and _debug("sending exit control to master");
	    $self->_master_ctl('exit');
	}
	$self->_kill_master;
    }
}

1;
__END__

=head1 NAME

Net::OpenSSH - Perl SSH client package implemented on top of OpenSSH

=head1 SYNOPSIS

  use Net::OpenSSH;

  my $ssh = Net::OpenSSH->new($host);
  $ssh->error and
    die "Couldn't establish SSH connection: ". $ssh->error;

  $ssh->system("ls /tmp") or
    die "remote command failed: " . $ssh->error;

  my @ls = $ssh->capture("ls");
  $ssh->error and
    die "remote ls command failed: " . $ssh->error;

  my ($out, $err) = $ssh->capture2("find /root");
  $ssh->error and
    die "remote find command failed: " . $ssh->error;

  my ($rin, $pid) = $ssh->pipe_in("cat >/tmp/foo") or
    die "pipe_in method failed: " . $ssh->error;

  print $rin, "hello\n";
  close $rin;

  my ($rout, $pid) = $ssh->pipe_out("cat /tmp/foo") or
    die "pipe_out method failed: " . $ssh->error;

  while (<$rout>) { print }
  close $rout;

  my ($in, $out ,$pid) = $ssh->open2("foo");
  my ($pty, $pid) = $ssh->open2pty("foo");
  my ($in, $out, $err, $pid) = $ssh->open3("foo");
  my ($pty, $err, $pid) = $ssh->open3pty("login");

  my $sftp = $ssh->sftp();
  $sftp->error and die "SFTP failed: " . $sftp->error;


=head1 DESCRIPTION

Net::OpenSSH is a secure shell client package implemented on top of
OpenSSH binary client (C<ssh>).

=head2 Under the hood

This package is implemented around the multiplexing feature found in
later versions of OpenSSH. That feature allows reuse of a previous SSH
connection for running new commands (I believe that OpenSSH 4.1 is the
first one to provide all the required functionality).

When a new Net::OpenSSH object is created, the OpenSSH C<ssh> client
is run in master mode, establishing a permanent (actually, for the
lifetime of the object) connection to the server.

Then, every time a new operation is requested a new C<ssh> process is
started in slave mode, effectively reusing the master SSH connection
to send the request to the remote side.

=head2 Net::OpenSSH Vs Net::SSH::.* modules

Why should you use Net::OpenSSH instead of any of the other Perl SSH
clients available?

Well, this is my (biased) opinion:

L<Net::SSH::Perl|Net::SSH::Perl> is not well maintained nowadays
(update: a new maintainer has stepped in so this situation could
change!!!), requires a bunch of modules (some of them very difficult
to install) to be acceptably efficient and has an API that is limited
in some ways.

L<Net::SSH2|Net::SSH2> is much better than Net::SSH::Perl, but not
completely stable yet. It can be very difficult to install on some
specific operative systems and its API is also limited, in the same
way as L<Net::SSH::Perl|Net::SSH::Perl>.

Using L<Net::SSH::Expect|Net::SSH::Expect>, in general, is a bad
idea. Handling interaction with a shell via Expect in a generic way
just can not be reliably done.

Net::SSH is just a wrapper around any SSH binary commands available on
the machine. It can be very slow as they establish a new SSH
connection for every operation performed.

In comparison, Net::OpenSSH is a pure perl module that doesn't have
any mandatory dependencies (obviously, besides requiring OpenSSH
binaries).

Net::OpenSSH has a very perlish interface. Most operations are
performed in a fashion very similar to that of the Perl builtins and
common modules (i.e. L<IPC::Open2|IPC::Open2>).

It is also very fast. The overhead introduced by launching a new ssh
process for every operation is not appreciable (at least on my Linux
box). The bottleneck is the latency intrinsic to the protocol, so
Net::OpenSSH is probably as fast as an SSH client can be.

Being based on OpenSSH is also an advantage: a proved, stable, secure
(to paranoic levels), interoperable and well maintained implementation
of the SSH protocol is used.

On the other hand, Net::OpenSSH does not work on Windows, not even
under Cygwin.

Net::OpenSSH specifically requires the OpenSSH SSH client (AFAIK, the
multiplexing feature is not available from any other SSH
client). However, note that it will interact with any server software,
not just servers running OpenSSH C<sshd>.

For password authentication, L<IO::Pty|IO::Pty> has to be
installed. Other modules and binaries are also required to implement
specific functionality (for instance
L<Net::SFTP::Foreign|Net::SFTP::Foreign>, L<Expect|Expect> or
L<rsync(1)|rsync(1)|>).

Net::OpenSSH and Net::SSH2 do not support version 1 of the SSH
protocol.

=head1 API

=head2 Optional arguments

Almost all methods in this package accept as first argument an
optional reference to a hash containing parameters (C<\%opts>). For
instance, these two method calls are equivalent:

  my $out1 = $ssh->capture(@cmd);
  my $out2 = $ssh->capture({}, @cmd);

=head2 Error handling

Most methods return undef (or an empty list) to indicate failure.

The L</error> method can always be used to explicitly check for
errors. For instance:

  my ($output, $errput) = $ssh->capture2({timeout => 1}, "find /");
  $ssh->error and die "ssh failed: " . $ssh->error;

=head2 Net::OpenSSH methods

These are the methods provided by the package:

=over 4

=item Net::OpenSSH->new($host, %opts)

Creates a new SSH master connection

C<$host> can be a hostname or an IP address. It may also
contain the name of the user, her password and the TCP port
number where the server is listening:

   my $ssh1 = Net::OpenSSH->new('jack@foo.bar.com');
   my $ssh2 = Net::OpenSSH->new('jack:secret@foo.bar.com:10022');
   my $ssh3 = Net::OpenSSH->new('jsmith@2001:db8::1428:57ab'); # IPv6

IPv6 addresses may optionally be enclosed in brackets:

   my $ssh4 = Net::OpenSSH->new('jsmith@[::1]:1022');

This method always succeeds in returning a new object. Error checking
has to be performed explicitly afterwards:

  my $ssh = Net::OpenSSH->new($host, %opts);
  $ssh->error and die "Can't ssh to $host: " . $ssh->error;

If you have problems getting Net::OpenSSH to connect to the remote
host read the troubleshooting chapter near the end of this document.

Accepted options:

=over 4

=item user => $user_name

Login name

=item port => $port

TCP port number where the server is running

=item passwd => $passwd

=item password => $passwd

User given password for authentication.

Note that using password authentication in automated scripts is a very
bad idea. When possible, you should use public key authentication
instead.


=item passphrase => $passphrase

X<passphrase>Uses given passphrase to open private key.

=item key_path => $private_key_path

Uses the key stored on the given file path for authentication.

=item gateway => $gateway

If the given argument is a gateway object as returned by
L<Net::OpenSSH::Gateway/find_gateway> method, use it to connect to
the remote host.

If it is a hash reference, call the C<find_gateway> method first.

For instance, the following code fragments are equivalent:

  my $gateway = Net::OpenSSH::Gateway->find_gateway(
          proxy => 'http://proxy.corporate.com');
  $ssh = Net::OpenSSH->new($host, gateway => $gateway);

and

  $ssh = Net::OpenSSH->new($host,
          gateway => { proxy => 'http://proxy.corporate.com'});

=item proxy_command => $proxy_command

Use the given command to establish the connection to the remote host
(see C<ProxyCommand> on L<ssh_config(5)>).

=item batch_mode => 1

Disables querying the user for password and passphrases.

=item ctl_dir => $path

Directory where the SSH master control socket will be created.

This directory and its parents must be writable only by the current
effective user or root, otherwise the connection will be aborted to
avoid insecure operation.

By default C<~/.libnet-openssh-perl> is used.

=item ssh_cmd => $cmd

Name or full path to OpenSSH C<ssh> binary. For instance:

  my $ssh = Net::OpenSSH->new($host, ssh_cmd => '/opt/OpenSSH/bin/ssh');

=item scp_cmd => $cmd

Name or full path to OpenSSH C<scp> binary.

By default it is inferred from the C<ssh> one.

=item rsync_cmd => $cmd

Name or full path to C<rsync> binary. Defaults to C<rsync>.

=item timeout => $timeout

Maximum acceptable time that can elapse without network traffic or any
other event happening on methods that are not immediate (for instance,
when establishing the master SSH connection or inside methods
C<capture>, C<system>, C<scp_get>, etc.).

See also L</Timeouts>.

=item kill_ssh_on_timeout => 1

This option tells Net::OpenSSH to kill the local slave SSH process
when some operation times out.

See also L</Timeouts>.

=item strict_mode => 0

By default, the connection will be aborted if the path to the socket
used for multiplexing is found to be non-secure (for instance, when
any of the parent directories is writable by other users).

This option can be used to disable that feature. Use with care!!!

=item async => 1

By default, the constructor waits until the multiplexing socket is
available. That option can be used to defer the waiting until the
socket is actually used.

For instance, the following code connects to several remote machines
in parallel:

  my (%ssh, %ls);
  # multiple connections are stablished in parallel:
  for my $host (@hosts) {
      $ssh{$host} = Net::OpenSSH->new($host, async => 1);
  }
  # then to run some command in all the hosts (sequentially):
  for my $host (@hosts) {
      $ssh{$host}->system('ls /');
  }

=item master_opts => [...]

Additional options to pass to the C<ssh> command when establishing the
master connection. For instance:

  my $ssh = Net::OpenSSH->new($host,
      master_opts => [-o => "ProxyCommand corkscrew httpproxy 8080 $host"]);

=item default_ssh_opts => [...]

Default slave SSH command line options for L</open_ex> and derived
methods.

For instance:

  my $ssh = Net::OpenSSH->new($host,
      default_ssh_opts => [-o => "ConnectionAttempts=0"]);

=item forward_agent => 1

Enables forwarding of the authentication agent.

This option can not be used when passing a passphrase (via
L</passphrase>) to unlock the login private key.

=item default_stdin_fh => $fh

=item default_stdout_fh => $fh

=item default_stderr_fh => $fh

Default I/O streams for L</open_ex> and derived methods (currently, that
means any method but L</pipe_in> and L</pipe_out> and I plan to remove
those exceptions soon!).

For instance:

  open my $stderr_fh, '>>', '/tmp/$host.err' or die ...;
  open my $stdout_fh, '>>', '/tmp/$host.log' or die ...;

  my $ssh = Net::OpenSSH->new($host, default_stderr_fh => $stderr_fh,
                                     default_stdout_fh => $stdout_fh);
  $ssh->error and die "SSH connection failed: " . $ssh->error;

  $ssh->scp_put("/foo/bar*", "/tmp")
    or die "scp failed: " . $ssh->error;

=item default_stdin_file = $fn

=item default_stdout_file = $fn

=item default_stderr_file = $fn

Opens the given filenames and use it as the defaults.

=item master_stdout_fh => $fh

=item master_stderr_fh => $fh

Redirect corresponding stdio streams of the master SSH process to
given filehandles.

=item master_stdout_discard => $bool

=item master_stderr_discard => $bool

Discard corresponding stdio streams.

=item expand_vars => $bool

Activates variable expansion inside command arguments and file paths.

See L</"Variable expansion"> below.

=item vars => \%vars

Initial set of variables.

=item external_master => 1

Instead of launching a new OpenSSH client in master mode, the module
tries to reuse an already existent one. C<ctl_path> must also be
passed when this option is set. See also L</get_ctl_path>.

Example:

  $ssh = Net::OpenSSH->new('foo', external_master => 1, ctl_path = $path);

=item default_encoding => $encoding

=item default_stream_encoding => $encoding

=item default_argument_encoding => $encoding

Set default encodings. See L</Data encoding>.

=item login_handler => \&custom_login_handler

Some remote SSH server may require a custom login/authentication
interaction not natively supported by Net::OpenSSH. In that cases, you
can use this option to replace the default login logic.

The callback will be invoked repeatly as C<custom_login_handler($ssh,
$pty, $data)> where C<$ssh> is the current Net::OpenSSH object, C<pty>
a L<IO::Pty> object attached to the slave C<ssh> process tty and
C<$data> a reference to an scalar you can use at will.

The login handler must return 1 after the login process has completed
successfully or 0 in case it still needs to do something else. If some
error happens, it must die.

Note, that blocking operations should not be performed inside the
login handler (at least if you want the C<async> and C<timeout>
features to work).

See also the sample script C<login_handler.pl> in the C<samples>
directory.

Usage of this option is incompatible with the C<password> and
C<passphrase> options, you will have to handle password or passphrases
from the custom handler yourself.

=back

=item $ssh->error

Returns the error condition for the last performed operation.

The returned value is a dualvar as $! (see L<perlvar/"$!">) that
renders an informative message when used in string context or an error
number in numeric context (error codes appear in
L<Net::OpenSSH::Constants|Net::OpenSSH::Constants>).

=item $ssh->get_user

=item $ssh->get_host

=item $ssh->get_port

Return the corresponding SSH login parameters.

=item $ssh->get_ctl_path

X<get_ctl_path>Returns the path to the socket where the OpenSSH master
process listens for new multiplexed connections.

=item ($in, $out, $err, $pid) = $ssh->open_ex(\%opts, @cmd)

X<open_ex>I<Note: this is a low level method that, probably, you don't need to use!>

That method starts the command C<@cmd> on the remote machine creating
new pipes for the IO channels as specified on the C<%opts> hash.

If C<@cmd> is omitted, the remote user shell is run.

Returns four values, the first three (C<$in>, C<$out> and C<$err>)
correspond to the local side of the pipes created (they can be undef)
and the fourth (C<$pid>) to the PID of the new SSH slave process. An
empty list is returned on failure.

Note that C<waitpid> has to be used afterwards to reap the
slave SSH process.

Accepted options:

=over 4

=item stdin_pipe => 1

Creates a new pipe and connects the reading side to the stdin stream
of the remote process. The writing side is returned as the first
value (C<$in>).

=item stdin_pty => 1

Similar to C<stdin_pipe>, but instead of a regular pipe it uses a
pseudo-tty (pty).

Note that on some OSs (i.e. HP-UX, AIX), ttys are not reliable. They
can overflow when large chunks are written or when data is
written faster than it is read.

=item stdin_fh => $fh

Duplicates C<$fh> and uses it as the stdin stream of the remote process.

=item stdin_file => $filename

=item stdin_file => \@open_args

Opens the file of the given name for reading and uses it as the remote
process stdin stream.

If an array reference is passed its contents are used as the arguments
for the underlying open call. For instance:

  $ssh->system({stdin_file => ['-|', 'gzip -c -d file.gz']}, $rcmd);

=item stdin_discard => 1

Uses /dev/null as the remote process stdin stream.

=item stdout_pipe => 1

Creates a new pipe and connects the writing side to the stdout stream
of the remote process. The reading side is returned as the second
value (C<$out>).

=item stdout_pty => 1

Connects the stdout stream of the remote process to the
pseudo-pty. This option requires C<stdin_pty> to be also set.

=item stdout_fh => $fh

Duplicates C<$fh> and uses it as the stdout stream of the remote
process.

=item stdout_file => $filename

=item stdout_file => \@open_args

Opens the file of the given filename and redirect stdout there.

=item stdout_discard => 1

Uses /dev/null as the remote process stdout stream.

=item stdinout_socket => 1

Creates a new socketpair, attachs the stdin an stdout streams of the
slave SSH process to one end and returns the other as the first value
(C<$in>) and undef for the second (C<$out>).

Example:

  my ($socket, undef, undef, $pid) = $ssh->open_ex({stdinout_socket => 1},
                                                   '/bin/netcat $dest');

See also L</open2socket>.

=item stdinout_dpipe => $cmd

=item stdinout_dpipe => \@cmd

Runs the given command locally attaching its stdio streams to those of
the remote SSH command. Conceptually it is equivalent to the
L<dpipe(1)> shell command.

=item stderr_pipe => 1

Creates a new pipe and connects the writing side to the stderr stream
of the remote process. The reading side is returned as the third
value (C<$err>).

Example:

  my $pid = $ssh->open_ex({stdinout_dpipe => 'vncviewer -stdio'},
                          x11vnc => '-inetd');

=item stderr_fh => $fh

Duplicates C<$fh> and uses it as the stderr stream of the remote process.

=item stderr_file => $filename

Opens the file of the given name and redirects stderr there.

=item stderr_to_stdout => 1

Makes stderr point to stdout.

=item tty => $bool

Tells ssh to allocate a pseudo-tty for the remote process. By default,
a tty is allocated if remote command stdin stream is attached to a
tty.

When this flag is set and stdin is not attached to a tty, the ssh
master and slave processes may generate spurious warnings about failed
tty operations. This is caused by a bug present in older versions of
OpenSSH.

=item close_slave_pty => 0

When a pseudo pty is used for the stdin stream, the slave side is
automatically closed on the parent process after forking the ssh
command.

This option dissables that feature, so that the slave pty can be
accessed on the parent process as C<$pty-E<gt>slave>. It will have to
be explicitly closed (see L<IO::Pty|IO::Pty>)

=item quote_args => $bool

See L</"Shell quoting"> below.

=item forward_agent => $bool

Enables/disables forwarding of the authentication agent.

This option can only be used when agent forwarding has been previously
requested on the constructor.

=item ssh_opts => \@opts

List of extra options for the C<ssh> command.

This feature should be used with care, as the given options are not
checked in any way by the module, and they could interfere with it.

=item tunnel => $bool

Instead of executing a command in the remote host, this option
instruct Net::OpenSSH to create a TCP tunnel. The arguments become the
target IP and port.

Example:

  my ($in, $out, undef, $pid) = $ssh->open_ex({tunnel => 1}, $IP, $port);

See also L</Tunnels>.

=item encoding => $encoding

=item argument_encoding => $encoding

Set encodings. See L</Data encoding>.

=back

Usage example:

  # similar to IPC::Open2 open2 function:
  my ($in_pipe, $out_pipe, undef, $pid) = 
      $ssh->open_ex( { stdin_pipe => 1,
                       stdout_pipe => 1 },
                     @cmd )
      or die "open_ex failed: " . $ssh->error;
  # do some IO through $in/$out
  # ...
  waitpid($pid);

=item $ssh->system(\%opts, @cmd)

Runs the command C<@cmd> on the remote machine.

Returns true on sucess, undef otherwise.

The error status is set to C<OSSH_SLAVE_CMD_FAILED> when the remote
command exits with a non zero code (the code is available from C<$?>,
see L<perlvar/"$?">).

Example:

  $ssh->system('ls -R /')
    or die "ls failed: " . $ssh->error";

As for C<system> builtin, C<SIGINT> and C<SIGQUIT> signals are
blocked.  (see L<perlfunc/system>). Also, setting C<$SIG{CHLD}> to
C<IGNORE> or to a custom signal handler will interfere with this
method.

Accepted options:

=over 4

=item stdin_data => $input

=item stdin_data => \@input

Sends the given data through the stdin stream to the remote
process.

For example, the following code creates a file on the remote side:

  $ssh->system({stdin_data => \@data}, "cat >/tmp/foo")
    or die "unable to write file: " . $ssh->error;

=item timeout => $timeout

The operation is aborted after C<$timeout> seconds elapsed without
network activity.

See also L</Timeouts>.

=item async => 1

Does not wait for the child process to exit. The PID of the new
process is returned.

Note that when this option is combined with C<stdin_data>, the given
data will be transferred to the remote side before returning control
to the caller.

See also the L</spawn> method documentation below.

=item stdin_fh => $fh

=item stdin_discard => $bool

=item stdout_fh => $fh

=item stdout_discard => $bool

=item stderr_fh => $fh

=item stderr_discard => $bool

=item stderr_to_stdout => $bool

=item stdinout_dpipe => $cmd

=item tty => $bool

See the L</open_ex> method documentation for an explanation of these
options.

=back

=item $ok = $ssh->test(\%opts, @cmd);

Runs the given command and returns its success/failure exit status as
1 or 0 respectively. Returns undef when something goes wrong in the
SSH layer.

Error status is not set to OSSH_SLAVE_CMD_FAILED when the remote
command exits with a non-zero code.

By default this method discards the remote command C<stdout> and
C<sterr> streams.

Usage example:

  if ($ssh->test(ps => -C => $executable)) {
    say "$executable is running on remote machine"
  }
  else {
    die "something got wrong: ". $ssh->error if $ssh->error;

    say "$executable is not running on remote machine"
  }

This method support the same set of options as C<system>, except
C<async> and C<tunnel>.

=item $output = $ssh->capture(\%opts, @cmd);

=item @output = $ssh->capture(\%opts, @cmd);

This method is conceptually equivalent to the perl backquote operator
(i.e. C<`ls`>): it runs the command on the remote machine and captures
its output.

In scalar context returns the output as a scalar. In list context
returns the output broken into lines (it honors C<$/>, see
L<perlvar/"$/">).

The exit status of the remote command is returned in C<$?>.

When an error happens while capturing (for instance, the operation
times out), the partial captured output will be returned. Error
conditions have to be explicitly checked using the L</error>
method. For instance:

  my $output = $ssh->capture({ timeout => 10 },
                             "echo hello; sleep 20; echo bye");
  $ssh->error and
      warn "operation didn't complete successfully: ". $ssh->error;
  print $output;

Setting C<$SIG{CHLD}> to a custom signal handler or to C<IGNORE> will
interfere with this method.

Accepted options:

=over 4

=item stdin_data => $input

=item stdin_data => \@input

=item timeout => $timeout

See L</Timeouts>.

=item stdin_fh => $fh

=item stdin_discard => $bool

=item stderr_fh => $fh

=item stderr_discard => $bool

=item stderr_to_stdout => $bool

=item tty => $bool

See the L</open_ex> method documentation for an explanation of these
options.

=back

=item ($output, $errput) = $ssh->capture2(\%opts, @cmd)

captures the output sent to both stdout and stderr by C<@cmd> on the
remote machine.

Setting C<$SIG{CHLD}> to a custom signal handler or to C<IGNORE> will
also interfere with this method.

The accepted options are:

=over 4

=item stdin_data => $input

=item stdin_data => \@input

See the L</system> method documentation for an explanation of these
options.

=item timeout => $timeout

See L</Timeouts>.

=item stdin_fh => $fh

=item stdin_discard => $bool

=item tty => $bool

See the L</open_ex> method documentation for an explanation of these
options.

=back

=item ($in, $pid) = $ssh->pipe_in(\%opts, @cmd)

X<pipe_in>This method is similar to the following Perl C<open> call

  $pid = open $in, '|-', @cmd

but running @cmd on the remote machine (see L<perlfunc/open>).

No options are currently accepted.

There is no need to perform a waitpid on the returned PID as it will
be done automatically by perl when C<$in> is closed.

Example:

  my ($in, $pid) = $ssh->pipe_in('cat >/tmp/fpp')
      or die "pipe_in failed: " . $ssh->error;
  print $in $_ for @data;
  close $in or die "close failed";

=item ($out, $pid) = $ssh->pipe_out(\%opts, @cmd)

X<pipe_out>Reciprocal to previous method, it is equivalent to

  $pid = open $out, '-|', @cmd

running @cmd on the remote machine.

No options are currently accepted.

=item ($in, $out, $pid) = $ssh->open2(\%opts, @cmd)

=item ($pty, $pid) = $ssh->open2pty(\%opts, @cmd)

=item ($socket, $pid) = $ssh->open2socket(\%opts, @cmd)

=item ($in, $out, $err, $pid) = $ssh->open3(\%opts, @cmd)

=item ($pty, $err, $pid) = $ssh->open3pty(\%opts, @cmd)

Shortcuts around L</open_ex> method.

=item $pid = $ssh->spawn(\%opts, @_)

X<spawn>Another L</open_ex> shortcut, it launches a new remote process
in the background and returns the PID of the local slave SSH process.

At some later point in your script, C<waitpid> should be called on the
returned PID in order to reap the slave SSH process.

For instance, you can run some command on several hosts in parallel
with the following code:

  my %conn = map { $_ => Net::OpenSSH->new($_, async => 1) } @hosts;
  my @pid;
  for my $host (@hosts) {
      open my($fh), '>', "/tmp/out-$host.txt"
        or die "unable to create file: $!";
      push @pid, $conn{$host}->spawn({stdout_fh => $fh}, $cmd);
  }

  waitpid($_, 0) for @pid;

Note that C<spawn> shouldn't be used to start detached remote
processes that may survive the local program (see also the L</FAQ>
about running remote processes detached).

=item ($socket, $pid) = $ssh->open_tunnel(\%opts, $dest_host, $port)

X<open_tunnel>Similar to L</open2socket>, but instead of running a
command, it opens a TCP tunnel to the given address. See also
L</Tunnels>.

=item $out = $ssh->capture_tunnel(\%opts, $dest_host, $port)

=item @out = $ssh->capture_tunnel(\%opts, $dest_host, $port)

X<capture_tunnel>Similar to L</capture>, but instead of running a command, it opens a
TCP tunnel.

Example:

  $out = $ssh->capture_tunnel({stdin_data => join("\r\n",
                                                  "GET / HTTP/1.0",
                                                  "Host: www.perl.org",
                                                  "", "") },
                              'www.perl.org', 80)

See also L</Tunnels>.

=item $ssh->scp_get(\%opts, $remote1, $remote2,..., $local_dir_or_file)

=item $ssh->scp_put(\%opts, $local, $local2,..., $remote_dir_or_file)

These two methods are wrappers around the C<scp> command that allow
transfers of files to/from the remote host using the existing SSH
master connection.

When transferring several files, the target argument must point to an
existing directory. If only one file is to be transferred, the target
argument can be a directory or a file name or can be ommited. For
instance:

  $ssh->scp_get({glob => 1}, '/var/tmp/foo*', '/var/tmp/bar*', '/tmp');
  $ssh->scp_put('/etc/passwd');

Both L</scp_get> and L</scp_put> methods return a true value when all
the files are transferred correctly, otherwise they return undef.

Accepted options:

=over 4

=item quiet => 0

By default, C<scp> is called with the quiet flag C<-q> enabled in
order to suppress progress information. This option allows reenabling
the progress indication bar.

=item verbose => 1

Calls C<scp> with the C<-v> flag.

=item recursive => 1

Copy files and directories recursively.

=item glob => 1

Allow expansion of shell metacharacters in the sources list so that
wildcards can be used to select files.

=item glob_flags => $flags

Second argument passed to L<File::Glob::bsd_glob|File::Glob/bsd_glob> function. Only
available for L</scp_put> method.

=item copy_attrs => 1

Copies modification and access times and modes from the original
files.

=item bwlimit => $Kbits

Limits the used bandwith, specified in Kbit/s.

=item timeout => $secs

The transfer is aborted if the connection does not finish before the
given timeout elapses. See also L</Timeouts>.

=item async => 1

Doesn't wait for the C<scp> command to finish. When this option is
used, the method returns the PID of the child C<scp> process.

For instance, it is possible to transfer files to several hosts in
parallel as follows:

  use Errno;
  my (%pid, %ssh);
  for my $host (@hosts) {
    $ssh{$host} = Net::OpenSSH->new($host, async => 1);
  }
  for my $host (@hosts) {
    $pid{$host} = $ssh{$host}->scp_put({async => 1}, $local_fn, $remote_fn)
      or warn "scp_put to $host failed: " . $ssh{$host}->error . "\n";
  }
  for my $host (@hosts) {
    if (my $pid = $pid{$host}) {
      if (waitpid($pid, 0) > 0) {
        my $exit = ($? >> 8);
        $exit and warn "transfer of file to $host failed ($exit)\n";
      }
      else {
        redo if ($! == EINTR);
        warn "waitpid($pid) failed: $!\n";
      }
    }
  }

=item stdout_fh => $fh

=item stderr_fh => $fh

=item stderr_to_stdout => 1

These options are passed unchanged to method L</open_ex>, allowing
capture of the output of the C<scp> program.

Note that C<scp> will not generate progress reports unless its stdout
stream is attached to a tty.

=back

=item $ssh->rsync_get(\%opts, $remote1, $remote2,..., $local_dir_or_file)

=item $ssh->rsync_put(\%opts, $local1, $local2,..., $remote_dir_or_file)

These methods use C<rsync> over SSH to transfer files from/to the remote
machine.

They accept the same set of options as the SCP ones.

Any unrecognized option will be passed as an argument to the C<rsync>
command (see L<rsync(1)>). Underscores can be used instead of dashes
in C<rsync> option names.

For instance:

  $ssh->rsync_get({exclude => '*~',
                   verbose => 1,
                   safe_links => 1},
                  '/remote/dir', '/local/dir');

=item $sftp = $ssh->sftp(%sftp_opts)

Creates a new L<Net::SFTP::Foreign|Net::SFTP::Foreign> object for SFTP
interaction that runs through the ssh master connection.

=item @call = $ssh->make_remote_command(\%opts, @cmd)

=item $call = $ssh->make_remote_command(\%opts, @cmd)

This method returns the arguments required to execute a command on the
remote machine via SSH. For instance:

  my @call = $ssh->make_remote_command(ls => "/var/log");
  system @call;

In scalar context, returns the arguments quoted and joined into one
string:

  my $remote = $ssh->make_remote_comand("cd /tmp/ && tar xf -");
  system "tar cf - . | $remote";

The options accepted are as follows:

=over 4

=item tty => $bool

Enables/disables allocation of a tty on the remote side.

=item forward_agent => $bool

Enables/disables forwarding of authentication agent.

This option can only be used when agent forwarding has been previously
requested on the constructor.

=item tunnel => 1

Return a command to create a connection to some TCP server reachable
from the remote host. In that case the arguments are the destination
address and port. For instance:

  $cmd = $ssh->make_remote_command({tunnel => 1}, $host, $port);

=back

=item $ssh->wait_for_master($async)

When the connection has been established by calling the constructor
with the C<async> option, this call allows one to advance the process.

If C<$async> is true, it will perform any work that can be done
inmediately without waiting (for instance, entering the password or
checking for the existence of the multiplexing socket) and then
return. If a false value is given, it will finalize the connection
process and wait until the multiplexing socket is available.

It returns a true value after the connection has been successfully
established. False is returned if the connection process fails or if
it has not yet completed (then, the L</error> method can be used to
distinguish between both cases).

=item $ssh->check_master

This method runs several checks to ensure that the master connection
is still alive.

=item $ssh->shell_quote(@args)

Returns the list of arguments quoted so that they will be restored to
their original form when parsed by the remote shell.

In scalar context returns the list of arguments quoted and joined.

Usually this task is done automatically by the module. See L</"Shell
quoting"> below.

This method can also be used as a class method.

Example:

  my $quoted_args = Net::OpenSSH->shell_quote(@args);
  system('ssh', '--', $host, $quoted_args);

=item $ssh->shell_quote_glob(@args)

This method is like the previous C<shell_quote> but leaves wildcard
characters unquoted.

It can be used as a class method also.

=item $ssh->set_expand_vars($bool)

Enables/disables variable expansion feature (see L</"Variable
expansion">).

=item $ssh->get_expand_vars

Returns current state of variable expansion feature.

=item $ssh->set_var($name, $value)

=item $ssh->get_var($name, $value)

These methods allow to change and to retrieve the value of the logical
value of the given name.

=item $ssh->get_master_pid

Returns the PID of the master SSH process

=item $ssh->master_exited

This methods allows one to tell the module that the master process has
exited when we get its PID from some external wait or waitpid
call. For instance:

  my $ssh = Net::OpenSSH->new('foo', async => 1);

  # create new processes
  # ...

  # rip them...
  my $master_pid = $ssh->master_pid;
  while ((my $pid = wait) > 0) {
    if ($pid == $master_pid) {
      $ssh->master_exited;
    }
  }

If your program rips the master process and this method is not called,
the OS could reassign the PID to a new unrelated process and the
module would try to kill it at object destruction time.

=item $pid = $ssh->sshfs_import(\%opts, $remote_fs, $local_mnt_point)

=item $pid = $ssh->sshfs_export(\%opts, $local_fs, $remote_mnt_point)

These methods use L<sshfs(1)> to import or export a file system
through the SSH connection.

They return the C<$pid> of the C<sshfs> process or of the slave C<ssh>
process used to proxy it. Killing that process unmounts the file
system, though, it may be probably better to use L<fusermount(1)>.

The options acepted are as follows:

=over

=item ssh_opts => \@ssh_opts

Options passed to the slave C<ssh> process.

=item sshfs_opts => \@sshfs_opts

Options passed to the C<sshfs> command. For instance, to mount the file
system in read-only mode:

  my $pid = $ssh->sshfs_export({sshfs_opts => [-o => 'ro']},
                               "/", "/mnt/foo");

=back

Note that this command requires a recent version of C<sshfs> to work (at
the time of writting, it requires the yet unreleased version available
from the FUSE git repository!).

See also the L<sshfs(1)> man page and the C<sshfs> and FUSE web sites
at L<http://fuse.sourceforge.net/sshfs.html> and
L<http://fuse.sourceforge.net/> respectively.

=back

=head2 Shell quoting

By default, when invoking remote commands, this module tries to mimic
perl C<system> builtin in regard to argument processing. Quoting
L<perlfunc/system>:

  Argument processing varies depending on the number of arguments.  If
  there is more than one argument in LIST, or if LIST is an array with
  more than one value, starts the program given by the first element
  of the list with arguments given by the rest of the list.  If there
  is only one scalar argument, the argument is checked for shell
  metacharacters, and if there are any, the entire argument is passed
  to the system's command shell for parsing (this is "/bin/sh -c" on
  Unix platforms, but varies on other platforms).

Take for example Net::OpenSSH L</system> method:

  $ssh->system("ls -l *");
  $ssh->system('ls', '-l', '/');

The first call passes the argument unchanged to ssh and it is executed
in the remote side through the shell which interprets metacharacters.

The second call escapes any shell metacharacters so that, effectively,
it is equivalent to calling the command directly and not through the
shell.

Under the hood, as the Secure Shell protocol does not provide for this
mode of operation and always spawns a new shell where it runs the
given command, Net::OpenSSH quotes any shell metacharacters in the
command list.

All the methods that invoke a remote command (system, open_ex, etc.)
accept the option C<quote_args> that allows one to force/disable shell
quoting.

For instance:

  $ssh->system({quote_args => 1}, "/path with spaces/bin/foo");

will correctly handle the spaces in the program path.

The shell quoting mechanism implements some extensions (for instance,
performing redirections to /dev/null on the remote side) that can be
dissabled with the option C<quote_args_extended>:

  $ssh->system({ stderr_discard => 1,
                 quote_args => 1, quote_args_extended => 0 },
               @cmd);

The option C<quote_args> can also be used to disable quoting when more
than one argument is passed. For instance, to get some pattern
expanded by the remote shell:

  $ssh->system({quote_args => 0}, 'ls', '-l', "/tmp/files_*.dat");

The method C<shell_quote> can be used to selectively quote some
arguments and leave others untouched:

  $ssh->system({quote_args => 0},
               $ssh->shell_quote('ls', '-l'),
               "/tmp/files_*.dat");

When the glob option is set in scp and rsync file transfer methods, an
alternative quoting method that knows about file wildcards and passes
them unquoted is used. The set of wildcards recognized currently is
the one supported by L<bash(1)>.

Another way to selectively use quote globing or fully disable quoting
for some specific arguments is to pass them as scalar references or
double scalar references respectively. In practice, that means
prepending them with one or two backslashes. For instance:

  # quote the last argument for globing:
  $ssh->system('ls', '-l', \'/tmp/my files/filed_*dat');

  # append a redirection to the remote command
  $ssh->system('ls', '-lR', \\'>/tmp/ls-lR.txt');

  # expand remote shell variables and glob in the same command:
  $ssh->system('tar', 'czf', \\'$HOME/out.tgz', \'/var/log/server.*.log');

As shell quoting is a tricky matter, I expect bugs to appear in this
area. You can see how C<ssh> is called, and the quoting used setting
the following debug flag:

  $Net::OpenSSH::debug |= 16;

Also, the current shell quoting implementation expects a shell
compatible with Unix C<sh> in the remote side. It will not work as
expected if for instance, the remote machine runs Windows, VMS or it
is a router.

As a workaround, do any required quoting yourself and pass the quoted
command as a string so that no further quoting is performed. For
instance:

  # for VMS
  $ssh->system('DIR/SIZE NFOO::USERS:[JSMITH.DOCS]*.TXT;0');

I plan to add support for different quoting mechanisms in the
future... if you need it now, just ask for it!!!

The current quoting mechanism does not handle possible aliases defined
by the remote shell. In that case, to force execution of the command
instead of the alias, the full path to the command must be used.

=head2 Timeouts

In order to stop remote processes when they timeout, the ideal aproach
would be to send them signals through the SSH connection as specified
by the protocol standard.

Unfortunately OpenSSH does not implement that feature so Net::OpenSSH
has to use other imperfect approaches:

=over 4

=item * close slave I/O streams

Closing the STDIN and STDOUT streams of the unresponsive remote
process will effectively deliver a SIGPIPE when it tries to access any
of them.

Remote processes may not access STDIN or STDOUT and even them,
Net::OpenSSH can only close these channels when it is capturing them,
so this approach does not always work.

=item * killing the local SSH slave process

This action may leave the remote process running, creating a remote
orphan so Net::OpenSSH does not use it unless the construction option
C<kill_ssh_on_timeout> is set.

=back

Luckily, future versions of OpenSSH will support signaling remote
processes via the mux channel.

=head2 Variable expansion

The variable expansion feature allows one to define variables that are
expanded automatically inside command arguments and file paths.

This feature is disabled by default. It is intended to be used with
L<Net::OpenSSH::Parallel|Net::OpenSSH::Parallel> and other similar
modules.

Variables are delimited by a pair of percent signs (C<%>), for
instance C<%HOST%>. Also, two consecutive percent signs are replaced
by a single one.

The special variables C<HOST>, C<USER> and C<PORT> are maintained
internally by the module and take the obvious values.

Variable expansion is performed before shell quoting (see L</"Shell
quoting">).

Some usage example:

  my $ssh = Net::OpenSSH->new('server.foo.com', expand_vars => 1);
  $ssh->set_var(ID => 42);
  $ssh->system("ls >/tmp/ls.out-%HOST%-%ID%");

will redirect the output of the C<ls> command to
C</tmp/ls.out-server.foo.com-42> on the remote host.

=head2 Tunnels

Besides running commands on the remote host, Net::OpenSSH also allows
to tunnel TCP connections to remote machines reachable from the SSH
server.

That feature is made available through the C<tunnel> option of the
L</open_ex> method, and also through wrapper methods L</open_tunnel>
and L</capture_tunnel> and most others where it makes sense.

Example:

  $ssh->system({tunnel => 1,
                stdin_data => "GET / HTTP/1.0\r\n\r\n",
                stdout_file => "/tmp/$server.res"},
               $server, 80)
      or die "unable to retrieve page: " . $ssh->error;

or capturing the output of several requests in parallel:

  my @pids;
  for (@servers) {
    my $pid = $ssh->spawn({tunnel => 1,
                           stdin_file => "/tmp/request.req",
                           stdout_file => "/tmp/$_.res"},
                          $_, 80);
    if ($pid) {
      push @pids, $pid;
    }
    else {
      warn "unable to spawn tunnel process to $_: " . $ssh->error;
    }
  }
  waitpid ($_, 0) for (@pids);

Under the hood, in order to create a tunnel, a new C<ssh> process is
spawned with the option C<-W${address}:${port}> (available from
OpenSSH 5.4 and upwards) making it redirect its stdio streams to the
remote given address. Unlike when C<ssh> C<-L> options is used to
create tunnels, no TCP port is opened on the local machine at any time
so this is a perfectly secure operation.

The PID of the new process is returned by the named methods. It must
be reaped once the pipe or socket handlers for the local side of the
tunnel have been closed.

OpenSSH 5.4 or later is required for the tunnels functionality to
work. Also, note that tunnel forwarding may be administratively
forbidden at the server side (see L<sshd(8)> and L<sshd_config(5)> or
the documentation provided by your SSH server vendor).

=head2 Data encoding

Net::OpenSSH has some support for transparently converting the data send
or received from the remote server to Perl internal unicode
representation.

The methods supporting that feature are those that move data from/to
Perl data structures (i.e. C<capture>, C<capture2>, C<capture_tunnel>
and methods supporting the C<stdin_data> option). Data accessed through
pipes, sockets or redirections is not affected by the encoding options.

It is also possible to set the encoding of the command and arguments
passed to the remote server on the command line.

By default, if no encoding option is given on the constructor or on the
method calls, Net::OpenSSH will not perform any encoding transformation,
effectively processing the data as latin1.

When data can not be converted between the Perl internal
representation and the selected encoding inside some Net::OpenSSH
method, it will fail with an C<OSSH_ENCODING_ERROR> error.

The supported encoding options are as follows:

=over 4

=item stream_encoding => $encoding

sets the encoding of the data send and received on capture methods.

=item argument_encoding => $encoding

sets the encoding of the command line arguments

=item encoding => $encoding

sets both C<argument_encoding> and C<stream_encoding>.

=back

The constructor also accepts C<default_encoding>,
C<default_stream_encoding> and C<default_argument_encoding> that set the
defaults.

=head2 Diverting C<new>

When a code ref is installed at C<$Net::OpenSSH::FACTORY>, calls to new
will be diverted through it.

That feature can be used to transparently implement connection
caching, for instance:

  my $old_factory = $Net::OpenSSH::FACTORY;
  my %cache;

  sub factory {
    my ($class, %opts) = @_;
    my $signature = join("\0", $class, map { $_ => $opts{$_} }, sort keys %opts);
    my $old = $cache{signature};
    return $old if ($old and $old->error != OSSH_MASTER_FAILED);
    local $Net::OpenSSH::FACTORY = $old_factory;
    $cache{$signature} = $class->new(%opts);
  }

  $Net::OpenSSH::FACTORY = \&factory;

... and I am sure it can be abused in several other ways!


=head1 3rd PARTY MODULE INTEGRATION

=head2 Expect

Sometimes you would like to use L<Expect> to control some program
running in the remote host. You can do it as follows:

  my ($pty, $pid) = $ssh->open2pty(@cmd)
      or die "unable to run remote command @cmd";
  my $expect = Expect->init($pty);

Then, you will be able to use the new Expect object in C<$expect> as
usual.

=head2 Net::Telnet

This example is adapted from L<Net::Telnet> documentation:

  my ($pty, $pid) = $ssh->open2pty({stderr_to_stdout => 1})
    or die "unable to start remote shell: " . $ssh->error;
  my $telnet = Net::Telnet->new(-fhopen => $pty,
                                -prompt => '/.*\$ $/',
                                -telnetmode => 0,
                                -cmd_remove_mode => 1,
                                -output_record_separator => "\r");

  $telnet->waitfor(-match => $telnet->prompt,
                   -errmode => "return")
    or die "login failed: " . $telnet->lastline;

  my @lines = $telnet->cmd("who");

  ...

  $telnet->close;
  waitpid($pid, 0);

=head2 mod_perl and mod_perl2

L<mod_perl> and L<mod_perl2> tie STDIN and STDOUT to objects that are
not backed up by real file descriptors at the operative system
level. Net::OpenSSH will fail if any of these handles is used
explicitly or implicitly when calling some remote command.

The workaround is to redirect them to C</dev/null> or to some file:

  open my $def_in, '<', '/dev/null' or die "unable to open /dev/null";
  my $ssh = Net::OpenSSH->new($host,
                              default_stdin_fh => $def_in);

  my $out = $ssh->capture($cmd1);
  $ssh->system({stdout_discard => 1}, $cmd2);
  $ssh->system({stdout_to_file => '/tmp/output'}, $cmd3);

Also, note that from a security stand point, running ssh from inside
the webserver process is not a great idea. An attacker exploiting some
Apache bug would be able to access the ssh keys and passwords and gain
unlimited access to the remote systems.

If you can, use a queue (as L<TheSchwartz|TheSchwartz>) or any other
mechanism to execute the ssh commands from another process running
under a different user account.

At a minimum, ensure that C<~www-data/.ssh> (or similar) is not
accessible through the web server!

=head2 Other modules

CPAN contains several modules that rely on SSH to perform their duties
as for example L<IPC::PerlSSH|IPC::PerlSSH> or
L<GRID::Machine|GRID::Machine>.

Often, it is possible to instruct them to go through a Net::OpenSSH
multiplexed connection employing some available constructor
option. For instance:

  use Net::OpenSSH;
  use IPC::PerlIPC;
  my $ssh = Net::OpenSSH->new(...);
  $ssh->error and die "unable to connect to remote host: " . $ssh->error;
  my @cmd = $ssh->make_remote_command('/usr/bin/perl');
  my $ipc = IPC::PerlSSH->new(Command => \@cmd);
  my @r = $ipc->eval('...');

or...

  use GRID::Machine;
  ...
  my @cmd = $ssh->make_remote_command('/usr/bin/perl');
  my $grid = GRID::Machine->new(command => \@cmd);
  my $r = $grid->eval('print "hello world!\n"');

In other cases, some kind of plugin mechanism is provided by the 3rd
party modules to allow for different transports. The method C<open2>
may be used to create a pair of pipes for transport in these cases.

=head1 TROUBLESHOOTING

Usually, Net::OpenSSH works out of the box, but when it fails, some
users have a hard time finding the cause of the problem. This mini
troubleshooting guide should help you to find and solve it.

=over 4

=item 1 - check the error message

Add in your script, after the Net::OpenSSH constructor call, an error
check:

  $ssh = Net::OpenSSH->new(...);
  $ssh->error and die "SSH connection failed: " . $ssh->error;

The error message will tell what has gone wrong.

=item 2 - OpenSSH version

Ensure that you have a version of C<ssh> recent enough:

  $ ssh -V
  OpenSSH_5.1p1 Debian-5, OpenSSL 0.9.8g 19 Oct 2007

OpenSSH version 4.1 was the first to support the multiplexing feature
and is the minimal required by the module to work. I advise you to use
the latest OpenSSH (currently 5.8) or at least a more recent
version.

The C<ssh_cmd> constructor option lets you select the C<ssh> binary to
use. For instance:

  $ssh = Net::OpenSSH->new($host,
                           ssh_cmd => "/opt/OpenSSH/5.8/bin/ssh")

Some hardware vendors (i.e. Sun) include custom versions of OpenSSH
bundled with the operative system. In priciple, Net::OpenSSH should
work with these SSH clients as long as they are derived from some
version of OpenSSH recent enough. Anyway, I advise you to use the real
OpenSSH software if you can!

=item 3 - run ssh from the command line

Check you can connect to the remote host using the same parameters you
are passing to Net::OpenSSH. In particular, ensure that you are
running C<ssh> as the same local user.

If you are running your script from a webserver, the user
would probably be C<www>, C<apache> or something alike.

Common problems are:

=over 4

=item *

Remote host public key not present in known_hosts file.

The SSH protocol uses public keys to identify the remote hosts so that
they can not be supplanted by some malicious third parties.

For OpenSSH, usually the server public key is stored in
C</etc/ssh/ssh_host_dsa_key.pub> or in
C</etc/ssh/ssh_host_rsa_key.pub> and that key should be copied into the
C<~/.ssh/known_hosts> file in the local machine (other SSH
implementations may use other file locations).

Maintaining the server keys when several hosts and clients are
involved may be somewhat inconvenient, so most SSH clients, by
default, when a new connection is stablished to a host whose key is
not in the C<known_hosts> file, show the key and ask the user if he
wants the key copied there.

=item *

Wrong remote host public key in known_hosts file.

This is another common problem that happens when some server is
replaced or reinstalled from scratch and its public key changes
becoming different to that installed on the C<known_hosts> file.

The easiest way to solve that problem is to remove the old key from
the C<known_hosts> file by hand using any editor and then to connect
to the server replying C<yes> when asked to save the new key.

=item *

Wrong permissions for the C<~/.ssh> directory or its contents.

OpenSSH client performs several checks on the access permissions of
the C<~/.ssh> directory and its contents and refuses to use them when
misconfigured. See the FILES section from the L<ssh(1)> man page.

=item *

Incorrect settings for password or public key authentication.

Check that you are using the right password or that the user public
key is correctly installed on the server.

=back

=item 4 - security checks on the multiplexing socket

Net::OpenSSH performs some security checks on the directory where the
multiplexing socket is going to be placed to ensure that it can not be
accessed by other users.

The default location for the multiplexing socket is under
C<~/.libnet-openssh-perl>. It can be changed using the C<ctl_dir> and
C<ctl_path> constructor arguments.

The requirements for that directory and all its parents are:

=over 4

=item *

They have to be owned by the user executing the script or by root

=item *

Their permission masks must be 0755 or more restrictive, so nobody
else has permissions to perform write operations on them.

=back

The constructor option C<strict_mode> disables these security checks,
but you should not use it unless you understand its implications.

=item 5 - file system must support sockets

Some file systems (as for instance FAT or AFS) do not support placing
sockets inside them.

Ensure that the C<ctl_dir> path does not lay into one of those file
systems.

=back

=head1 DEBUGGING

Debugging of Net::OpenSSH internals is controlled through the variable
C<$Net::OpenSSH::debug>.  Every bit of this variable activates
debugging of some subsystem as follows:

=over 4

=item bit 1 - errors

Dumps changes on the internal object attribute where errors are stored.

=item bit 2 - ctl_path

Dumps information about ctl_path calculation and the tests performed
on that directory in order to decide if it is secure to place the
multiplexing socket inside.

=item bit 4 - connecting

Dumps information about the establishment of new master connections.

=item bit 8 - commands and arguments

Dumps the command and arguments for every system/exec call.

=item bit 16 - command execution

Dumps information about the progress of command execution.

=item bit 32 - destruction

Dumps information about the destruction of Net::OpenSSH objects and
the termination of the SSH master processes.

=item bit 64 - IO loop

Dumps information about the progress of the IO loop on capture
operations.

=item bit 128 - IO hexdumps

Generates hexdumps of the information that travels through the SSH
streams inside capture operations.

=item bit 512 - OS tracing of the master process

Use the module L<Net::OpenSSH::OSTracer> to trace the SSH master
process at the OS level.

=back

For instance, in order to activate all the debugging flags, you can
use:

  $Net::OpenSSH::debug = ~0;

Note that the meaning of the flags and the information generated is
only intended for debugging of the module and may change without
notice between releases.

=head1 FAQ

Frequent questions about the module:

=over

=item Connecting to switches, routers, etc.

B<Q>: I can't get the method C<system>, C<capture>, etc., to work when
connecting to some router, switch, etc. What I am doing wrong?

B<A>: Roughly, the SSH protocol allows for two modes of operation:
command mode and interactive mode.

Command mode is designed to run single commands on the remote host. It
opens an SSH channel between both hosts, ask the remote computer to
run some given command and when it finnish the channel is closed. It
is what you get, for instance, when you run something as...

  $ ssh my.unix.box cat foo.txt

... and it is also the way Net::OpenSSH runs commands on the remote
host.

Interactive mode launches a shell on the remote hosts with its stdio
streams redirected to the local ones so that the user can
transparently interact with it.

Some devices (as probably the one you are using) do not run an
standard, general purpose shell (i.e. C<bash>, C<csh> or C<ksh>) but
some custom program specially targeted and limited to the task of
configuring the device.

Usually, the SSH server running on these devices does not support
command mode. It unconditionally attachs the restricted shell to any
incoming SSH connection and waits for the user to enter commands
through the redirected stdin stream.

The only way to workaround this limitation is to make your script talk
to the restricted shell (1-open a new SSH session, 2-wait for the
shell prompt, 3-send a command, 4-read the output until you get to the
shell prompt again, repeat from 3). The best tool for this task is
probably L<Expect>, used alone, as wrapped by L<Net::SSH::Expect> or
combined with Net::OpenSSH (see L</Expect>).

There are some devices that support command mode but that only accept
one command per connection. In that cases, using L<Expect> is also
probably the best option.

=item Connection fails

B<Q>: I am unable to make the module connect to the remote host...

B<A>: Have you read the trubleshooting section? (see
L</TROUBLESHOOTING>).

=item Disable StrictHostKeyChecking

B<Q>: Why don't you run C<ssh> with C<StrictHostKeyChecking=no>?

B<A>: Using C<StrictHostKeyChecking=no> relaxes the default security
level of SSH and it will be relatively easy to end with a
misconfigured SSH (for instance, when C<known_hosts> is unwriteable)
that could be forged to connect to a bad host in order to perform
man-in-the-middle attacks, etc.

I advice you to do not use that option unless you fully understand its
implications from a security point of view.

If you want to use it anyway, past it to the constructor:

  $ssh = Net::OpenSSH->new($host,
           master_opts => [-o => "StrictHostKeyChecking=no"],
           ...);


=item child process 14947 does not exist: No child processes

B<Q>: Calls to C<system>, C<capture> or C<capture2> fail with the
previous error, what I am doing wrong?

B<A>: That usually happens when C<$SIG{CHLD}> is set to C<IGNORE> or
to some custom handler reaping child processes by itself. In order to
solve the problem just disable the handler during the method call:

  local $SIG{CHLD};
  $ssh->system($cmd);

=item child process STDIN/STDOUT/STDERR is not a real system file
handle

B<Q>: Calls to C<system>, C<capture>, etc. fail with the previous
error, what's happening?

B<A>: The reported stdio stream is closed or is not attached to a real
file handle (i.e. it is a tied handle). Redirect it to C</dev/null> or
to a real file:

  my $out = $ssh->capture({stdin_discard => 1, stderr_to_stdout => 1},
                          $cmd);

See also the L<mod_perl> entry above.

=item Solaris (and AIX and probably others)

B<Q>: I was trying Net::OpenSSH on Solaris and seem to be running into
an issue...

B<A>: The SSH client bundled with Solaris is an early fork of OpenSSH
that does not provide the multiplexing functionality required by
Net::OpenSSH. You will have to install the OpenSSH client.

Precompiled packages are available from Sun Freeware
(L<http://www.sunfreeware.com>). There, select your OS version an CPU
architecture, download the OpenSSH package and its dependencies and
install them. Note that you do B<not> need to configure Solaris to use
the OpenSSH server C<sshd>.

Ensure that OpenSSH client is in your path before the system C<ssh> or
alternatively, you can hardcode the full path into your scripts
as follows:

  $ssh = Net::OpenSSH->new($host,
                           ssh_cmd => '/usr/local/bin/ssh');

AIX and probably some other unixen, also bundle SSH clients lacking
the multiplexing functionality and require installation of the real
OpenSSH.

=item Can't change working directory

B<Q>: I want to run some command inside a given remote directory but I
am unable to change the working directory. For instance:

  $ssh->system('cd /home/foo/bin');
  $ssh->systen('ls');

does not list the contents of C</home/foo/bin>.

What am I doing wrong?

B<A>: Net::OpenSSH (and, for that matter, all the SSH modules
available from CPAN but L<Net::SSH::Expect>) runs every command in a
new session so most shell builtins that are run for its side effects
become useless (i.e. C<cd>, C<export>, C<ulimit>, C<umask>, etc.,
usually, you can list them running help from the shell).

A work around is to combine several commands in one, for instance:

  $ssh->system('cd /home/foo/bin && ls');

Note the use of the shell C<&&> operator instead of C<;> in order to
abort the command as soon as any of the subcommands fail.

Also, several commands can be combined into one while still using the
multi-argument quoting feature as follows:

  $ssh->system(@cmd1, \\'&&', @cmd2, \\'&&', @cmd3, ...);

=item Running detached remote processes

B<Q>: I need to be able to ssh into several machines from my script,
launch a process to run in the background there, and then return
immediately while the remote programs keep running...

B<A>: If the remote systems run some Unix/Linux variant, the right
approach is to use L<nohup(1)> that will disconnect the remote process
from the stdio streams and to ask the shell to run the command on the
background. For instance:

  $ssh->system("nohup $long_running_command &");

Also, it may be possible to demonize the remote program. If it is
written in Perl you can use L<App::Daemon> for that (actually, there
are several CPAN modules that provided that kind of functionality).

In any case, note that you shouldn't use L</spawn> for that.

=item MaxSessions server limit reached

B<Q>: I created an C<$ssh> object and then fork a lot children
processes which use this object. When the children number is bigger
than C<MaxSessions> as defined in sshd configuration (defaults to 10),
trying to fork new remote commands will prompt the user for the
password.

B<A>: When the slave SSH client gets a response from the remote
servers saying that the maximum number of sessions for the current
connection has been reached, it fallbacks to open a new direct
connection without going through the multiplexing socket.

To stop that for happening, the following hack can be used:

  $ssh = Net::OpenSSH->new(host,
      default_ssh_opts => ['-oConnectionAttempts=0'],
      ...);

=item Running remote commands with sudo

B<Q>: How can I run remote commands using C<sudo> to become root first?

B<A>: The simplest way is to tell C<sudo> to read the password from
stdin with the C<-S> flag and to do not use cached credentials
with the C<-k> flag. You may also like to use the C<-p> flag to tell
C<sudo> to print an empty prompt. For instance:

  my @out = $ssh->capture({stdin_data => "$sudo_passwd\n"},
                          'sudo', '-Sk',
                          '-p', '',
                          '--',
                          @cmd);

If the version of sudo installed on the remote host does not support
the C<-S> flag (it tells sudo to read the password from its STDIN
stream), you can do it as follows:

  my @out = $ssh->capture({tty => 1,
                           stdin_data => "$sudo_passwd\n"},
                           'sudo', '-k',
                           '-p', '',
                           '--',
                           @cmd);

This may generate an spurious and harmless warning from the SSH master
connection (because we are requesting allocation of a tty on the
remote side and locally we are attaching it to a regular pair of
pipes).

If for whatever reason the methods described above fail, you can
always revert to using Expect to talk to the remote C<sudo>. See the
C<sample/expect.pl> script from this module distribution.

=back

=head1 SEE ALSO

OpenSSH client documentation L<ssh(1)>, L<ssh_config(5)>, the project
web L<http://www.openssh.org> and its FAQ
L<http://www.openbsd.org/openssh/faq.html>. L<scp(1)> and
L<rsync(1)>. The OpenSSH Wikibook
L<http://en.wikibooks.org/wiki/OpenSSH>.

L<Net::OpenSSH::Gateway> for detailed instruction about how to get
this module to connect to hosts through proxies and other SSH gateway
servers.

Core perl documentation L<perlipc>, L<perlfunc/open>,
L<perlfunc/waitpid>.

L<IO::Pty|IO::Pty> to known how to use the pseudo tty objects returned
by several methods on this package.

L<Net::SFTP::Foreign|Net::SFTP::Foreign> provides a compatible SFTP
implementation.

L<Expect|Expect> can be used to interact with commands run through
this module on the remote machine (see also the C<expect.pl> and
<autosudo.pl> scripts in the sample directory).

L<SSH::OpenSSH::Parallel> is an advanced scheduler that allows one to run
commands in remote hosts in parallel. It is obviously based on
Net::OpenSSH.

L<SSH::Batch|SSH::Batch> allows one to run remote commands in parallel in
a cluster. It is build on top on C<Net::OpenSSH> also.

Other Perl SSH clients: L<Net::SSH::Perl|Net::SSH::Perl>,
L<Net::SSH2|Net::SSH2>, L<Net::SSH|Net::SSH>,
L<Net::SSH::Expect|Net::SSH::Expect>, L<Net::SCP|Net::SCP>,
L<Net::SSH::Mechanize|Net::SSH::Mechanize>.

L<Net::OpenSSH::Compat> is a package offering a set of compatibility
layers for other SSH modules on top of Net::OpenSSH.

L<IPC::PerlSSH|IPC::PerlSSH>, L<GRID::Machine|GRID::Machine> allow
execution of Perl code in remote machines through SSH.

L<SSH::RPC|SSH::RPC> implements an RPC mechanism on top of SSH using
Net::OpenSSH to handle the connections.

=head1 BUGS AND SUPPORT

Support for the gateway feature is highly experimental.

Support for data encoding is experimental.

Support for taint mode is experimental.

Tested on Linux, OpenBSD, NetBSD and Solaris with OpenSSH 5.1 to 5.9.

Net::OpenSSH does not work on Windows. OpenSSH multiplexing feature
requires passing file handles through sockets, something that is not
supported by any version of Windows.

It doesn't work on VMS either... well, probably, it doesn't work on
anything not resembling a modern Linux/Unix OS.

To report bugs send an email to the address that appear below or use
the CPAN bug tracking system at L<http://rt.cpan.org>.

B<Post questions related to how to use the module in Perlmonks>
L<http://perlmonks.org/>, you will probably get faster responses than
if you address me directly and I visit Perlmonks quite often, so I
will see your question anyway.

The source code of this module is hosted at GitHub:
L<http://github.com/salva/p5-Net-OpenSSH>.

=head2 Commercial support

Commercial support, professional services and custom software
development around this module are available through my current
company. Drop me an email with a rough description of your
requirements and we will get back to you ASAP.

=head2 My wishlist

If you like this module and you're feeling generous, take a look at my
Amazon Wish List: L<http://amzn.com/w/1WU1P6IR5QZ42>.

Also consider contributing to the OpenSSH project this module builds
upon: L<http://www.openssh.org/donations.html>.

=head1 TODO

- *** add tests for scp, rsync and sftp methods

- *** add support for more target OSs (quoting, OpenVMS, Windows & others)

- better timeout handling in system and capture methods

- make L</pipe_in> and L</pipe_out> methods L</open_ex> based

- add C<scp_cat> and similar methods

- async disconnect

- currently wait_for_master does not honor timeout

- auto_discard_streams feature for mod_perl2 and similar environments

- add proper shell quoting for Windows (see
  L<http://blogs.msdn.com/b/twistylittlepassagesallalike/archive/2011/04/23/everyone-quotes-arguments-the-wrong-way.aspx>).

Send your feature requests, ideas or any feedback, please!

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008-2012 by Salvador FandiE<ntilde>o
(sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
