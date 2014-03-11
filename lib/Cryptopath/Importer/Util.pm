#!/usr/bin/perl -w
package Cryptopath::Importer::Util;

use JSON::XS;
use strict;

BEGIN {
	require Exporter;
	our @ISA = qw(Exporter);
	our @EXPORT = qw( &send_message &recv_message );
	our @EXPORT_OK = qw( create_message enqueue_message );
}

sub create_message {
	my ($msg, $data) = @_;

	return encode_json( { cmd => $msg, data => $data });
}

sub enqueue_message {
	my ($list, $msg, $data) = @_;
	die "Array required" unless ref($list) eq "ARRAY";
	push @$list, create_message($msg, $data);
}

sub send_message {
	my ($socket, $msg, $data) = @_;
	my $json;

	if ( defined $data ) {
		# Normal message
		$json = create_message($msg, $data);
	} else {
		# Already encoded, from a queue
		$json = $msg;
	}

	syswrite $socket, length($json) . "\n";
	syswrite $socket, $json;
}

sub recv_message {
	my ($socket) = @_;
	my $len = "";
	my $buf = "";
	my $json;

	my $ret = 1;

	while($buf ne "\n" && $ret ) {
		$ret = sysread($socket, $buf, 1);
		$len .= $buf;
	}

	chomp $len;

	return if (defined $ret && $ret == 0); # Socket closed

	die "Sysread error in length: $!" unless (defined $ret);
	die "Bad length: $len" unless ($len =~ /^\d+$/);
	die "Length out of range: $len" if ( $len < 1 || $len > 1024*1024);

	$ret = sysread($socket, $json, $len) || return undef;

	die "Sysread error in content: $!" unless (defined $ret);
	die "No content" unless ($ret > 0);


	my $decoded = decode_json($json);
	return $decoded;
}

1;
