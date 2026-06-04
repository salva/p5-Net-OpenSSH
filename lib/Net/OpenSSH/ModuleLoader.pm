package Net::OpenSSH::ModuleLoader;

use strict;
use warnings;
use Carp;

our %loaded_module;

use Exporter qw(import);
our @EXPORT = qw(_load_module);

sub _load_module {
    my ($module, $version) = @_;
    defined $module or croak "bad Perl module name";
    $module =~ /\A[A-Za-z_]\w*(?:::\w+)*\z/
        or croak "bad Perl module name $module";
    $loaded_module{$module} ||= do {
        my $err;
        do {
            local ($@, $SIG{__DIE__});
            (my $path = "$module.pm") =~ s!::!/!g;
            my $ok = eval { require $path; 1 };
            $err = $@;
            $ok;
        } or croak "unable to load Perl module $module: $err";
    };
    if (defined $version) {
        local ($@, $SIG{__DIE__});
        eval { $module->VERSION($version); 1 }
            or croak $@ || "$module version $version required";
    }
    1
}

1;
