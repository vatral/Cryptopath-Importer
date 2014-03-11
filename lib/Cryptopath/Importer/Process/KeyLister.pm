#!/usr/bin/perl -w
package Cryptopath::Importer::Process::KeyLister;
use strict;
use Moose;
use BerkeleyDB;

extends 'Cryptopath::Importer::Process';

has 'datadir'   => (is => 'rw', isa => 'Str', default => '/srv/sks/dump/KDB');


sub run {
	my ($self) = @_;
	my $exit;

	my %keys;
	my $db = tie %keys, 'BerkeleyDB::Btree', -Filename => $self->datadir . "/keyid", -Flags => DB_RDONLY;

	my $end_reached;

	while(!$exit) {
		my $msg = $self->recv();

		if ( $msg->{cmd} eq "get_keys" ) {
			my @ret;

			for(my $i=0; $i< $msg->{data}->{count}; $i++ ) {
				my ($key, $val);

				if (!$end_reached) {
					($key, $val) = each %keys;
					$end_reached = 1 if (!defined $key);
				}

				if (!$end_reached) {
					my $k = unpack("H*", $key);
					push @ret, $k;
				}
			}


			$self->send("keys", { list => \@ret });
		}
	}
}




1;


