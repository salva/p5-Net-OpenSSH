#!/usr/bin/perl

use strict;
use warnings;
use Net::OpenSSH;
use File::Temp qw(tempfile);

my $host = shift // 'foo';

my ($merr_fh, $merr_fn) = tempfile();

open my $master_stderr_fh,  '>', "/tmp/$$.stderr"
    or die "Couldn't open master  stderr file.\n";

my $ssh = Net::OpenSSH->new($host,
                            'master_stderr_fh' => $merr_fh);

if ($ssh->error) {
    my $detail = do {
        open my $efh, '<', $merr_fn or die "unable to reopen $merr_fn: $!";
        local $/;
        <$efh>
    };
    print "SSH connection failed: " . $ssh->error . "\n  $detail\n";
}

unlink $merr_fn;


