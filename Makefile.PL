use 5.005;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
	      NAME	=> 'Net::SAP',
	      VERSION_FROM => 'lib/Net/SAP.pm', # finds $VERSION
	      PREREQ_PM => {
			    'IO::Socket::Multicast' => 0.20,
			    'Compress::Zlib' => 1.14,
			    'Test' => 1,
			   },
	      LIBS	=> '',		# e.g., '-lm' 
	      DEFINE	=> '',	# e.g., '-DHAVE_SOMETHING' 
	      INC	=> '',		# e.g., '-I/usr/include/other' 
	      
	      ABSTRACT_FROM	=> 'lib/Net/SAP.pm',	# retrieve abstract from module
	      AUTHOR        => 'Nicholas Humfrey',
);
