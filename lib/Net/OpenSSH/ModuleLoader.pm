package Net::OpenSSH::ModuleLoader;

use strict;
use warnings;
use Carp;

our %loaded_module;

use Exporter qw(import);
our @EXPORT = qw(_load_module);

sub _load_module {
    my ($module, $version) = @_;
    $loaded_module{$module} ||= do {
	do {
	    local ($@, $SIG{__DIE__});
	    eval "require $module; 1"
	} or croak "unable to load Perl module $module";
        1
    };
    if (defined $version) {
	local ($@, $SIG{__DIE__});
	my $mv = eval "\$${module}::VERSION" || 0;
	(my $mv1 = $mv) =~ s/_\d*$//;
	croak "$module version $version required, $mv is available"
	    if $mv1 < $version;
    }
    1
}

1;
