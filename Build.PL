use Module::Build;

my $build = Module::Build->new
    (
	module_name => 'Net::SAP',
	license => 'perl',
	build_requires => {
		'Module::Build' => '0.25'
	},
	requires => {
		'perl'	=> '5.5.0',
		'IO::Socket::Multicast' => '0.20',
		'Compress::Zlib' => '1.14',
		'Test' => '1.00'
	}
    );
$build->create_build_script;
