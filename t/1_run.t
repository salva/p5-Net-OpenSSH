#!/usr/bin/perl

use strict;
use warnings;
use Cwd;
use File::Spec;
use Test::More;

use lib "./t";
use common;

use Net::OpenSSH;
my $timeout = 15;

my $PS_P = ($^O =~ /sunos|solaris/i ? 'ps -p' : 'ps p');

# $Net::OpenSSH::debug = -1;


my $V = `ssh -V 2>&1`;
my ($ver, $num) = $V =~ /^(OpenSSH_(\d+\.\d+).*)$/msi;

plan skip_all => 'OpenSSH 4.1 or later required'
    unless (defined $num and $num >= 4.1);

chomp $ver;
diag "\nSSH client found: $ver.\nTrying to connect to localhost, timeout is ${timeout}s.\n";

my $ssh = Net::OpenSSH->new('localhost', timeout => $timeout, strict_mode => 0);

# fallback
if ($ssh->error and $num > 4.7) {
    diag "Connection failed... trying fallback aproach";
    my $sshd_cmd = sshd_cmd;
    if (defined $sshd_cmd) {
	my $here = File::Spec->rel2abs("t");
	diag "sshd command found at $sshd_cmd.\n" .
	    "Faking connection, timeout is ${timeout}s.\n" .
	    "Using configuration from '$here'.";

	chmod 0600, "$here/test_user_key", "$here/test_server_key";;

	my @sshd_cmd = ($sshd_cmd, '-i',
			 -h => "$here/test_server_key",
			 -o => "AuthorizedKeysFile $here/test_user_key.pub",
			 -o => "StrictModes no",
			 -o => "PasswordAuthentication no",
			 -o => "PermitRootLogin yes");
	s/(\W)/\\$1/g for @sshd_cmd;

	$ssh = Net::OpenSSH->new('localhost', timeout => $timeout, strict_mode => 0,
				 master_opts => [-o => "ProxyCommand @sshd_cmd",
						 -o => "StrictHostKeyChecking no",
						 -o => "NoHostAuthenticationForLocalhost yes",
						 -i => "$here/test_user_key"]);
    }
    else {
	diag "sshd command not found!"
    }
}

plan skip_all => 'Unable to establish SSH connection to localhost!'
    if $ssh->error;

plan tests => 23;

sub shell_quote {
    my $txt = shift;
    $txt =~ s|([^a-zA-Z0-9+-\./])|\\$1|g;
    $txt
}

my $muxs = $ssh->get_ctl_path;
ok(-S $muxs, "mux socket exists");
is((stat $muxs)[2] & 0777, 0600, "mux socket permissions");

my $cwd = cwd;
my $sq_cwd = shell_quote $cwd;

my @ls_good= sort `ls $sq_cwd`;
my @ls = sort $ssh->capture({stderr_to_stdout => 1}, "ls $sq_cwd");
is("@ls", "@ls_good");

my @lines = map "foo $_\n", 1..10;
my $lines = join('', @lines);

my ($in, $pid) = $ssh->pipe_in("cat > $sq_cwd/test.dat");
ok($ssh->error == 0);
ok($in);
ok(defined $pid);

print $in $_ for @lines;
my @ps = `$PS_P $pid`;
ok(grep(/ssh/i, @ps));
ok(close $in);
@ps = `$PS_P $pid`;
ok(!grep(/ssh/i, @ps));

ok(-f "$cwd/test.dat");

my ($output, $errput) = $ssh->capture2("cat $sq_cwd/test.dat");
is($errput, '', "errput");
is($output, $lines, "output") or diag $output;

$output = $ssh->capture({stdin_data => \@lines}, "cat");
is ($output, $lines);

$output = $ssh->capture({stdin_data => \@lines, stderr_to_stdout => 1}, "cat >&2");
is ($output, $lines);

($output, $errput) = $ssh->capture2("cat $sq_cwd/test.dat 1>&2");
is ($errput, $lines);
is ($output, '');

my $fh = $ssh->pipe_out("cat $sq_cwd/test.dat");
ok($fh, "pipe_out");
$output = join('', <$fh>);
is($output, $lines, "pipe_out lines");

my $string = q(#@$#$%&(@#_)erkljgfd'' 345345' { { / // ///foo);

$output = $ssh->capture(echo => $string);
chomp $output;
is ($output, $string, "quote_args");

eval { $ssh->capture({foo => 1}, 'bar') };
ok($@ =~ /option/ and $@ =~ /foo/);

is ($ssh->shell_quote('/foo/'), '/foo/');
is ($ssh->shell_quote('./foo*/bar&biz;'), './foo\\*/bar\\&biz\\;');
is ($ssh->_quote_args({quote_args => 1, glob_quoting => 1}, './foo*/bar&biz;'), './foo*/bar\\&biz\\;');
