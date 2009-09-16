use 5.008;
use ExtUtils::MakeMaker;

warn <<EOW if 0;
============================================================================
Warning, Net::OpenSSH 0.24 introduced several backward incompatible changes.
Read the Changes file for the details!!!
============================================================================

EOW

WriteMakefile( NAME => 'Net::OpenSSH',
               VERSION_FROM => 'lib/Net/OpenSSH.pm',
               PREREQ_PM => { Test::More => 0, },
               AUTHOR => 'Salvador Fandino <sfandino@yahoo.com>' );
