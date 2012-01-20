package Net::OpenSSH::OSTracer;

use strict;
use warnings;

use POSIX;

our $cmd;
our $type;
our $output;
our $sudo;
our $delay;

our @EXTRA_ARGS;

my %type_by_os = (linux   => 'strace',
                  openbsd => 'ktrace',
                  freebsd => 'ktrace',
                  bsd     => 'ktruss',
                  'hp-ux' => 'tusc',
                  aix     => 'truss',
                  solaris => 'truss');

sub trace {
    my $class = shift;
    my ($cmd, $type) = ($cmd, $type); # copy globals


    if (not defined $type) {
        my $os = lc $^O;
        if ( defined $cmd and $cmd =~ /([sk]trace|k?truss|tusc)$/) {
            $type = $1;
        }
        elsif ($os =~ /(linux|openbsd|freebsd|bsd|hp-ux|aix|solaris)/) {
            $type = $type_by_os{$1};
        }
        else {
            Net::OpenSSH::_debug("unable to determine tracer type for OS $os");
            return;
        }
    }

    my $output1 = (defined $output ? $output : "/tmp/net_openssh_master") . ".$$";
    my $file = "$output1.$type";
    my $err = "$output1.txt";

    $cmd = $type unless defined $cmd;

    my @args;
    if ($type eq 'strace') {
        @args = (-o => $file, -p => $$, -s => 1024, '-fx');
    }
    elsif ($type eq 'ktruss') {
        @args = (-o => $file, -p => $$, -m => 1024, '-d');
    }
    elsif ($type eq 'ktrace') {
        @args = (-f => $file, -p => $$, '-id');
    }
    elsif ($type eq 'tusc') {
        @args = (-o => $file, -b => 1024, '-fa', $$)
    }
    elsif ($type eq 'truss') {
        @args = (-o => $file, -p => $$, -s => 1024, '-f');
    }
    else {
        Net::OpenSSH::_debug("tracer type $type not supported");
        return
    }

    my @cmd = (defined $sudo ? ($sudo, '-A', $cmd) : $cmd);

    my $pid = fork;
    unless ($pid) {
        unless (defined $pid) {
            Net::OpenSSH::_debug("unable to launch tracer, fork failed: $!");
            return;
        }
        my ($in, $out);
        if (open $in, '</dev/null'      and
            open $out, '>', $err        and
            POSIX::dup2(fileno $in, 0)  and
            POSIX::dup2(fileno $out, 1) and
            POSIX::dup2(fileno $out, 2)) {
            exec (@cmd, @EXTRA_ARGS, @args);
        }
        else {
            eval { Net::OpenSSH::_debug("Unable to redirect tracer IO: $!") };
        }
        POSIX::_exit(1);
    }
    sleep (defined $delay ? $delay : 1); # wait for the tracer to come up
    Net::OpenSSH::_debug("tracer attached, ssh pid: $$, tracer pid: $pid");
    1;
}

1;

__END__

=head1 NAME

Net::OpenSSH::OSTracer - trace ssh master process at the OS level

=head1 SYNOPSIS

    use Net::OpenSSH;
    $Net::OpenSSH::debug |= 512;

    Net::OpenSSH->new($host)->system("echo hello world");

    system "less /tmp/net_openssh_master.*.strace";

=head1 DESCRIPTION

This is a Net::OpenSSH helper module that allows you to use your
favourite OS level tracer (i.e, strace, truss, ktruss, tusc, etc.) to
trace the ssh master process easyly.

=cut
