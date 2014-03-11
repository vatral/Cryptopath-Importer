#!/usr/bin/perl -w
package Cryptopath::Importer::Process::KeyChecker;

use strict;
use DBI;
use DBD::Pg;
use Moose;

extends 'Cryptopath::Importer::Process';

has 'connection_string' => ( is => 'rw', isa => 'Str', default => 'dbi:Pg:dbname=cryptopath');
has 'db_username'       => ( is => 'rw', isa => 'Str', default => '');
has 'db_password'       => ( is => 'rw', isa => 'Str', default => '');



$| = 1;


sub run {
	my ($self) = @_;

	my $dbh = DBI->connect($self->connection_string, $self->db_username, $self->db_password, { AutoCommit => 0 });

	$self->{sth_chk_key} = $dbh->prepare("SELECT 1 FROM keys WHERE short_key_id = ?");

	my $exit;

	while(!$exit) {
		my $msg = $self->recv;
		if ( $msg->{cmd} eq "check_keys" ) {
			my @in_db;
			my @not_in_db;

			foreach my $key ( @{ $msg->{data}->{list} } ) {
				if ( $self->key_exists($key) ) {
					push @in_db, $key;
				} else {
					push @not_in_db, $key;
				}
			}
	
			$self->send("verified_keys", { list => \@not_in_db } ) if ( scalar @not_in_db );
			$self->send("existing_keys", { list => \@in_db } ) if ( scalar @in_db );

		}
	}
}
	

sub key_exists {
	my ($self, $id) = @_;
	my $uid = substr($id, -16);

	my $uid_bin = pack("H*", $uid);
	$self->{sth_chk_key}->bind_param(1, $uid_bin,  { pg_type => DBD::Pg::PG_BYTEA } );
	$self->{sth_chk_key}->execute();

	if ( $self->{sth_chk_key}->fetchrow_arrayref() ) {
		return 1;
	}


	return 0;
}

1;
