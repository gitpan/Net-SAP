package Net::SAP;

################
#
# SAP: Session Announcement Protocol (rfc2974) Packet parser
#
# Nicholas Humfrey
# njh@ecs.soton.ac.uk
#
#
# port 9875
#
# groups
# v4           : 224.2.127.254
# v6 Node-local: FF01::2:7FFE
# v6 Link-local: FF02::2:7FFE
# v6 Site-local: FF05::2:7FFE
# v6  Org-local: FF08::2:7FFE
# v6     Global: FF0E::2:7FFE
#

use strict;
use IO::Socket::Multicast;
use Compress::Zlib;
use vars qw/$VERSION/;

$VERSION="0.02";



sub new {
    my $class = shift;
    my $self = {
    	'group'	=> '224.2.127.254',
    	'port'	=> 9875,
    	'proto'	=> 'udp',
    };
    
    
    # Create the multicast socket
    my $sock = IO::Socket::Multicast->new(
    		Proto => $self->{'proto'},
    		LocalPort => $self->{'port'});
    return undef unless ($sock);
    
	# Join the SAP multicast group
	$sock->mcast_add( $self->{'group'} );

	
    $self->{'sock'} = $sock;
	bless $self, $class;
	return $self;
}

#
# Blocks until a valid SAP packet is received
#
#
sub receive {
	my ($self) = @_;
	my $sap_packet = undef;
	
	while (!defined $sap_packet) {
		my $data;
		
		# rfc2327 says the max size of an SDP file is 1k
		next unless $self->{'sock'}->recv($data,2048);
		
		# Try and parse the packet
		$sap_packet = $self->parse_sap_packet( $data );
	}
	
	return $sap_packet;
}


sub parse_sap_packet {
	my ($self, $packet) = @_;
	my $sap= {};
	my $pos=0;
	
	# grab the first 32bits of the packet
	my ($vartec, $auth_len, $id_hash) = unpack("CCn",substr($packet,$pos,4)); $pos+=4;
	
 	$sap->{'v'} = (($vartec & 0xE0) >> 5);	# Version (1)
 	$sap->{'a'} = (($vartec & 0x10) >> 4);	# Address type (0=v4, 1=v6)
# 	$sap->{'r'} = (($vartec & 0x08) >> 3);	# Reserved
 	$sap->{'t'} = (($vartec & 0x04) >> 2);	# Message Type (0=announce, 1=delete)
 	$sap->{'e'} = (($vartec & 0x02) >> 1);	# Encryped (0=no, 1=yes)
 	$sap->{'c'} = (($vartec & 0x01) >> 0);	# Compressed (0=no, 1=yes)
 	
 	# Show warning if unsupported SAP packet version
 	if ($sap->{'v'} != 0 and $sap->{'v'} != 1) {
 		warn "Unsupported SAP packet version: $sap->{'v'}.\n";
 		return undef;
 	}
 	
	
 	$sap->{'auth_len'} = $auth_len;
 	$sap->{'msg_id_hash'} = sprintf("0x%4.4X", $id_hash);
 	
 	if ($sap->{'a'} == 0) {
 		# IPv4 address
 		$sap->{'origin_ip'} = sprintf("%d.%d.%d.%d", unpack("CCCC", substr($packet,$pos,4))); $pos+=4;
 	} else {
 		# IPv6 address
 		warn "Net::SAP doesn't currently support IPv6.\n";
 		return undef;
 	}
 	
 	
 	# Get authentication data if it exists
 	if ($sap->{'auth_len'}) {
 		$sap->{'auth_data'} = substr($packet,$pos,$sap->{'auth_len'});
 		$pos+=$sap->{'auth_len'};
 		warn "Net::SAP doesn't currently support encrypted SAP packets.\n";
 		return undef;
 	}
 	
 	
 	# Decompress the payload with zlib
 	my $payload = substr($packet,$pos);
	if ($sap->{'c'}) {
		my $inf = inflateInit();
		unless (defined $inf) {
			warn "Failed to initalise zlib to decompress SAP packet";
			return undef;
		} else {
			$payload = $inf->inflate( $payload );
			unless (defined $payload) {
				warn "Failed to decompress SAP packet";
				return undef;
			}
		}
	}


 	# Check the next three bytes, to see if it is the start of an SDP file
 	if ($payload =~ /^v=\d+/) {
  		$sap->{'payload_type'} = 'application/sdp';
 		$sap->{'payload'} = $payload;
	} else {
		my $index = index($payload, "\x00");
		if ($index==-1) {
			$sap->{'payload_type'} = "unknown";
			$sap->{'payload'} = $payload;
		} else {
			$sap->{'payload_type'} = substr( $payload, 0, $index );
			$sap->{'payload'} = substr( $payload, $index+1 );
 		}
 	}

	return $sap;
}



sub close {
	my $self=shift;
	
	# Leave the SAP multicast group
	$self->{'sock'}->mcast_drop( $self->{'group'} );
	
	# Close the socket
	$self->{'sock'}->close();
	
	undef $self->{'sock'};
}


sub DESTROY {
    my $self=shift;
    
    if (exists $self->{'sock'} and defined $self->{'sock'}) {
    	$self->close();
    }
}


1;

__END__

=pod

=head1 NAME

Net::SAP - Session Announcement Protocol (rfc2974) packet parser

=head1 SYNOPSIS

  use Net::SAP;

  my $sap = Net::SAP->new();

  my $packet = $sap->receive();

  $sap->close();


=head1 DESCRIPTION

Net::SAP currently provides basic functionality for receiving and parsing
SAP (RFC2974) multicast packets.

=head2 CONSTRUCTORS

=over 4

=item $sap = Net::SAP->new()

The new() method is the constructor for the Net::SAP class.
When you create a Net::SAP object, it automatically joins
the SAP multicast group, ready to start receiving packets.

=back

=head2 METHODS

=over 4

=item $packet = $sap->receive()

This method blocks until a valid SAP packet has been received.
The packet is parsed, decompressed and returned as a hashref:

 {
    'a' => 0,	# 0 is origin address is IPv4
    		# 1 if the address IPv6
    'c' => 0,	# 1 if packet was compressed
    'e' => 0,	# 1 if packet was encrypted
    't' => 0,	# 0 if this is an advertizement
    		# 1 for session deletion
    'v' => 1,	# SAP Packet format version number

    # Message ID Hash as 16bit hex number
    'msg_id_hash' => 0x1287,

    # Length of the authentication data
    'auth_len' => 0,	

    # The authentication data as binary
    'auth_data' => '',

    # IP the announcement originated from
    'origin_ip' => '152.78.104.83',	

    # MIME type of the payload
    'payload_type' => 'application/sdp',

    # The payload - usually an SDP file
    'payload' => '',

 };


=item $sap->close()

Leave the SAP multicast group and close the socket.

=back

=head1 TODO

=over

=item Add IPv6 support

=item Packet decryption and validation

=item Add support for creating and sending packets.

=item Add test script as part of build process

=item Return perl object (Net::SAP::Packet ?) instead of hash ?

=item Better documentation ?

=back

=head1 SEE ALSO

perl(1), IO::Socket::Multicast(3)

http://www.ietf.org/rfc/rfc2974.txt

=head1 AUTHOR

Nicholas Humfrey, njh@ecs.soton.ac.uk

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 University of Southampton

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.005 or,
at your option, any later version of Perl 5 you may have available.

=cut
