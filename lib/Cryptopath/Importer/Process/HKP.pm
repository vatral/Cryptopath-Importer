#!/usr/bin/perl -w
package Cryptopath::Importer::Process::HKP;
use strict;
use GnuPG::Interface;
use File::Temp qw( tempdir );
use Moose;

extends 'Cryptopath::Importer::Process';

has 'gpg_bin'   => (is => 'rw', isa => 'Str', default => '/usr/bin/gpg');
has 'keyserver' => (is => 'rw', isa => 'Str', default => "hkp://localhost:11371" );


sub run {
	my ($self) = @_;
	my $exit;

	while(!$exit) {
		my $msg = $self->recv();

		if ( $msg->{cmd} eq "fetch_keys" ) {
			my $homedir  = $msg->{data}->{homedir};
			my $key_list = $msg->{data}->{keys};

			$self->fetch_keys($homedir, @$key_list);
			$self->send("keys_received", { homedir => $homedir, keys => $key_list });
		}
	}
}



sub fetch_keys {
	my ($self, $homedir, @keys)  = @_;

	print "Receiving keys: " . join(' ', @keys) . "\n";
	my @cmd = ($self->gpg_bin, "--homedir", $homedir, "--keyserver", $self->keyserver, "-q", "--recv-keys", @keys);

	print "Executing: " . join(' ', @cmd) . "\n";
	open(my $gpg, "-|", @cmd);
	my $ret = <$gpg>;
	close $gpg;

	return $ret;
}

1;


