#!/usr/bin/perl
#
# This example script reads packets
# and prints the hashref of the packets
# using Data::Dumper.
#

use Net::SAP;
use Data::Dumper;
use strict;


my $sap = Net::SAP->new();

while(1) {
	my $packet = $sap->receive();

	print Dumper( $packet )."\n";
}

$sap->close();

