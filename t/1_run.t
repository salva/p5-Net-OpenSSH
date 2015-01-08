#!/usr/bin/perl

use strict;
use warnings;
use Cwd;

use lib "./t";
use common;

use Net::OpenSSH;
use Net::OpenSSH::Constants qw(OSSH_ENCODING_ERROR OSSH_MASTER_FAILED);

if ($^O =~ /MSWin|cygwin/i) {
    plan skip_all => 'Core functionality does not work on Windows';
}

my $timeout = 15;
my $fallback;

my $PS = find_cmd 'ps';
defined $PS or plan skip_all => "ps command not found";
my $LS = find_cmd('ls');
defined $LS or plan skip_all => "ls command not found";
my $CAT = find_cmd('cat');
defined $CAT or plan skip_all => "cat command not found";
my $ECHO = find_cmd('echo');
defined $ECHO or plan skip_all => "echo command not found";

my $PS_P = ($^O =~ /^(?:sunos|solaris|aix)/i ? "$PS -p" : "$PS p");

# $Net::OpenSSH::debug = ~0;

plan skip_all => 'Your shell introduces garbage on the output when running commands, ' .
                 'check your shell configuration files (i.e. ~/.bashrc)'
    unless shell_is_clean;

my $V = `ssh -V 2>&1`;
my ($ver, $num) = (defined $V ? $V =~ /^(OpenSSH_(\d+\.\d+).*)$/msi : ());

plan skip_all => 'OpenSSH 4.1 or later required'
    unless (defined $num and $num >= 4.1);

chomp $ver;
diag "\nSSH client found: $ver.\nTrying to connect to localhost, timeout is ${timeout}s.\n";

# are we running on the background?
my $bg;
eval {
    no warnings;
    require POSIX;
    my $pgrp = POSIX::getpgrp();
    if (open my $tty, "</dev/tty") {
        my $p = POSIX::tcgetpgrp(fileno $tty);
        if ($p >= 0 and $p != $pgrp) {
            $bg = 1;
        }
    }
    else {
        my $p = POSIX::tcgetpgrp(0);
        if ($p >= 0 and $p != $pgrp) {
            $bg = 1;
        }
    }
};
diag $@ if $@;

$bg and diag "Testing script is running on the background, enabling OpenSSH batch mode.";

my %ctor_opts = (host => 'localhost',
                 timeout => $timeout,
                 strict_mode => 0,
                 batch_mode => ($bg ? 1 : 0),
                 master_opts => [-o => "StrictHostKeyChecking no"]);

my $ssh = Net::OpenSSH->new(%ctor_opts);

# fallback, disabled because it is currently broken!
if (0 and $ssh->error and $num > 4.7) {
    diag "Connection failed... trying fallback aproach";
    my $sshd_cmd = sshd_cmd;
    if (defined $sshd_cmd) {
	my $here = File::Spec->rel2abs("t");
	diag join("\n", "sshd command found at $sshd_cmd.",
                  "Faking connection, timeout is ${timeout}s.",
                  "Using configuration from '$here'", "");
	chmod 0600, "$here/test_user_key", "$here/test_server_key";;
	my @sshd_cmd = ($sshd_cmd, '-i',
			-h => "$here/test_server_key",
			-o => "AuthorizedKeysFile $here/test_user_key.pub",
			-o => "StrictModes no",
			-o => "PasswordAuthentication no",
			-o => "PermitRootLogin yes",
                        -o => "PrintMotd no" );
	s/(\W)/\\$1/g for @sshd_cmd;

	$ssh = Net::OpenSSH->new(%ctor_opts,
                                 master_opts => [ #'-vvv',
                                                 -o => "ProxyCommand @sshd_cmd",
                                                 -o => "StrictHostKeyChecking no",
                                                 -o => "NoHostAuthenticationForLocalhost yes",
                                                 -o => "UserKnownHostsFile $here/known_hosts",
                                                 -o => "GlobalKnownHostsFile $here/known_hosts"],
                                 key_path => "$here/test_user_key");
        $fallback = 1;
    }
    else {
	diag "sshd command not found!"
    }
}

plan skip_all => 'Unable to establish SSH connection to localhost!'
    if $ssh->error;

plan tests => 46;

sub shell_quote {
    my $txt = shift;
    $txt =~ s|([^\w+\-\./])|\\$1|g;
    $txt
}

my $muxs = $ssh->get_ctl_path;
ok(-S $muxs, "mux socket exists");

SKIP: {
    skip "AIX ignores the socket permissions", 1 if $^O =~ /^aix/;
    is((stat $muxs)[2] & 0677, 0600, "mux socket permissions");
}

my $cwd = cwd;
my $sq_cwd = shell_quote $cwd;

my $rshell = $ssh->capture($ECHO => \\'$SHELL');
my $rshell_is_csh = ($rshell =~ /\bt?csh$/);

my @ls_good= sort `$LS $sq_cwd`;
my @ls = sort $ssh->capture({stderr_to_stdout => 1}, "$LS $sq_cwd");
is("@ls", "@ls_good");

my @lines = map "foo $_\n", 1..10;
my $lines = join('', @lines);

my ($in, $pid) = $ssh->pipe_in("$CAT > $sq_cwd/test.dat");
ok($ssh->error == 0);
ok($in);
ok(defined $pid);

print $in $_ for @lines;
my @ps = `$PS_P $pid`;
ok(grep(/ssh/i, @ps));
ok(close $in);
@ps = `$PS_P $pid`;
ok(!grep(/ssh/i, @ps), "pipe_in SSH proccess is reaped on close");

ok(-f "$cwd/test.dat");

my ($output, $errput) = $ssh->capture2("$CAT $sq_cwd/test.dat");
is($errput, '', "errput");
is($output, $lines, "output") or diag $output;

{
    my $ssh2 = Net::OpenSSH->new(external_master => 1, ctl_path => $ssh->get_ctl_path);
    my ($output, $errput) = $ssh2->capture2("$CAT $sq_cwd/test.dat");
    is($errput, '', "external_master 1");
    is($output, $lines, "external_master 2") or diag $output;
    # DESTROY $ssh2
}
ok($ssh->check_master, "check_master") or diag "error: ", $ssh->error;

$ssh->system({stdout_file => ['>', "$sq_cwd/test.dat.deleteme"],
              stderr_discard => 1 }, "$CAT $sq_cwd/test.dat");
is ($ssh->error, 0, "system ok");
$output = $ssh->capture("$CAT $sq_cwd/test.dat.deleteme");
is ($ssh->error, 0, "system ok") or diag "error: ", $ssh->error;
is ($output, $lines, "redirection works");
unlink "$sq_cwd/test.dat.deleteme";

$output = $ssh->capture(cd => $sq_cwd, \\'&&', $CAT => 'test.dat');
is ($output, $lines) or diag "error: ", $ssh->error;

$output = $ssh->capture({stdin_data => \@lines}, $CAT);
is ($output, $lines);

SKIP: {
    skip "remote shell is csh", 3 if $rshell_is_csh;
    $output = $ssh->capture({stdin_data => \@lines, stderr_to_stdout => 1}, "$CAT >&2");
    is ($output, $lines);

    ($output, $errput) = $ssh->capture2("$CAT $sq_cwd/test.dat 1>&2");
    is ($errput, $lines);
    is ($output, '');
}

my $fh = $ssh->pipe_out("$CAT $sq_cwd/test.dat");
ok($fh, "pipe_out");
$output = join('', <$fh>);
is($output, $lines, "pipe_out lines");

my $string = q(#@$#$%&(@#_)erkljgfd'' 345345' { { / // ///foo bar////doz '''' heloo);

$output = $ssh->capture(echo => $string);
chomp $output;
is ($output, $string, "quote_args");

$string .= "\nline1\nline2";

SKIP: {
    skip "remote shell is csh", 1 if $rshell_is_csh;
    $output = $ssh->capture(echo => $string);
    chomp $output;
    is ($output, $string, "quote_args with new lines");
}

eval { $ssh->capture({foo => 1}, 'bar') };
ok($@ =~ /option/ and $@ =~ /foo/);

is ($ssh->shell_quote('/foo/'), '/foo/');
is ($ssh->shell_quote('./foo*/bar&biz;'), "'./foo*/bar&biz;'");
is (Net::OpenSSH->shell_quote('./foo*/bar&biz;'), "'./foo*/bar&biz;'");
is ($ssh->_quote_args({quote_args => 1, glob_quoting => 1}, './foo*/bar&biz;'), "./foo*/bar'&biz;'");
is ($ssh->shell_quote_glob('./foo*/bar&biz;'),  "./foo*/bar'&biz;'");
is (Net::OpenSSH->shell_quote_glob('./foo*/bar&biz;'),  "./foo*/bar'&biz;'");

$ssh->set_expand_vars(1);
$ssh->set_var(FOO => 'Bar');
is ($ssh->shell_quote(\\'foo%FOO%foo%%foo'), 'fooBarfoo%foo');
is ($ssh->shell_quote('foo%FOO%foo%%foo'), "'fooBarfoo\%foo'");
$ssh->set_expand_vars(0);
is ($ssh->shell_quote(\\'foo%FOO%foo%%foo'), 'foo%FOO%foo%%foo');
is (Net::OpenSSH->shell_quote(\\'foo%FOO%foo%%foo'), 'foo%FOO%foo%%foo');

my $enne = "letra e\xf1e";

$ssh->capture({encoding => 'ascii'}, $ECHO => $enne);
is ($ssh->error+0, OSSH_ENCODING_ERROR, "bad encoding");
$ssh->wait_for_master;
is ($ssh->error, 0, "wait_for_master resets error");
$ssh->capture({encoding => 'ascii'}, $ECHO => $enne);
is ($ssh->error+0, OSSH_ENCODING_ERROR, "bad encoding");
my $captured_enne = $ssh->capture({encoding => 'latin1'}, $ECHO => $enne);
chomp $captured_enne;
is ($ssh->error+0, 0, "good encoding");
is ($captured_enne, $enne, "capture and encoding");

my $rcmd = $ssh->make_remote_command($ECHO => 'hello');
my $pipe_out = readpipe $rcmd;
chomp $pipe_out;
is ($pipe_out, 'hello', 'make_remote_command');

eval {
    my $ssh3 = $ssh;
    undef $ssh;
    die "some text";
};
like($@, qr/^some text/, 'DESTROY should not clobber $@');

SKIP: {
    skip "no login with default key", 1 if $fallback;
    my $ssh4;
    for my $passwd (qw(foo bar)) {
        $ssh4 = eval { Net::OpenSSH->new(%ctor_opts, passwd => $passwd, master_stderr_discard => 1) };
        if ($@) {
            $@ =~ /IO::Pty/ and skip "no IO::Pty", 1;
            diag "unexpected error: $@";
        }
        last if $ssh4->error;
    }
    is ($ssh4->error+0, OSSH_MASTER_FAILED, "bad password");
}

