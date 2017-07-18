package mod_perl_openssh;

use strict;
use warnings;

use Apache2::Const qw(OK);
use Apache2::RequestRec;
use Apache2::RequestUtil;

use Net::OpenSSH;
$Net::OpenSSH::debug = -1;
use constant SSH_HOST => 'localhost';

sub handler ($$) {
    my($class, $r) = @_;

    open my $stdin, '<', '/dev/null' or die "unable to open /dev/null";
    my $ssh = Net::OpenSSH->new(SSH_HOST,
                                default_stdin_fh => $stdin,
                                # master_opts => ["-vvv"]
                               );
    die $ssh->error if $ssh->error;
    my $date = $ssh->capture({stderr_file => '/dev/null'}, "date");
    warn "error: " . $ssh->error .", date: $date";
    $r->content_type("text/plain");
    print("hello, the date at " . $ssh->get_host
          . " is $date\n");
    OK;
}

1;

__END__
