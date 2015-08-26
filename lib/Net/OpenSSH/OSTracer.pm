package Net::OpenSSH::OSTracer;

our $VERSION = '0.65_06';

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
                  netbsd  => 'ktrace',
                  bsd     => 'ktrace',
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
        elsif ($os =~ /(linux|openbsd|freebsd|netbsd|bsd|hp-ux|aix|solaris)/) {
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
        @args = (-o => $file, -faep => $$);
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

This is a Net::OpenSSH helper module that allows you to trace the
master C<ssh> process at the operating system level using the proper
utility available in your system (e.g., C<strace>, C<truss>,
C<ktruss>, C<tusc>, etc.).

This feature can be used when debugging your programs or to report
bugs on the module.

It is enabled setting the flag 512 on the C<$Net::OpenSSH::debug> variable:

  $Net::OpenSSH::debug |= 512;

By default the output files of the tracer are saved as
C</tmp/net_openssh_master.$pid.$tracer_type>.

Also, the output send by the tracer to stdout/stderr is saved as
C</tmp/net_openssh_master.$pid.txt>.

The module can be configured through the following global variables:

=over 4

=item $Net::OpenSSH::OSTracer::type

By default, the module decides which tracer to use in base to the
operating system name. This variable allows one to select a different
tracer.

Currently accepted types are: C<strace> (Linux), C<ktrace> (*BSD),
C<tusc> (HP-UX) and C<truss> (Solaris and AIX).

=item $Net::OpenSSH::OSTracer::cmd

Command to execute for tracing the C<ssh> process.

By default, it infers it from the tracer type selected.

=item $Net::OpenSSH::OSTracer::output

Basename for the destination file. The PID of the C<ssh> process and
the tracer type will be appended.

=item $Net::OpenSSH::OSTracer::sudo

This variable can be used to request the tracer to be run with C<sudo>
(some operating systems as for example Ubuntu, do not allow one to
attach tracers, even to your own processes, unless you do it as root).

The variable has to be set with the path of the C<sudo> binary. For
instance:

  $Net::OpenSSH::OSTracer::sudo = '/usr/bin/sudo';

If you need to pass a password to C<sudo>, set the environment
variable C<SUDO_ASKPASS>. For instance:

  SUDO_ASKPASS=/usr/bin/ssh-askpass

=item $Net::OpenSSH::OSTracer::delay

This variable can be used to delay the C<ssh> execution so that the
tracer can attach the process first. This is specially handy when
using C<sudo> with a password.

=back

=head1 BUGS

This module has not been tested under all the operating systems is
says to support.

If you find any problem, just report it, please!

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Salvador FandiE<ntilde>o
(sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
