#!/usr/bin/perl -w
package Cryptopath::Importer::Process::Postgres;

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

	$self->{sth_add_key} = $dbh->prepare("INSERT INTO keys (key_id, fingerprint) VALUES (?, ?)");
	$self->{sth_add_sig} = $dbh->prepare("INSERT INTO signatures (key_id, signed_by_id) VALUES (?,?)");
	$self->{sth_chk_key} = $dbh->prepare("SELECT 1 FROM keys WHERE key_id = ?");

	my $exit;

	while(!$exit) {
		my $msg = $self->recv;

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

sub insert_sigs {
	my ($self, $id, $fpr, $sigs) = @_;

	my $uid = substr($id, -16);

	print $uid . ": FPR $fpr, SIGS: " . join(', ', sort keys %$sigs ) . "\n";

	my $fp_bin  = pack("H*", $fpr);
	my $uid_bin = pack("H*", $uid);
	

	$self->{sth_add_key}->bind_param(1, $uid_bin, { pg_type => DBD::Pg::PG_BYTEA } );
	$self->{sth_add_key}->bind_param(2, $fp_bin, { pg_type => DBD::Pg::PG_BYTEA } );
	$self->{sth_add_key}->execute;

	$self->{sth_add_sig}->bind_param(1, $uid_bin, { pg_type => DBD::Pg::PG_BYTEA } );

	foreach my $sig ( keys %$sigs ) {
		my $sig_bin = pack("H*", $sig);

		$self->{sth_add_sig}->bind_param(2, $sig_bin, { pg_type => DBD::Pg::PG_BYTEA } );
		$self->{sth_add_sig}->execute;
	}


	print ".";
}

1;
