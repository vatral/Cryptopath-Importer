#!/usr/bin/perl -w
package Cryptopath::Importer::Process::ListSignatures;
use strict;
use GnuPG::Interface;
use File::Temp qw( tempdir );
use Moose;
use Data::Dumper qw(Dumper);

extends 'Cryptopath::Importer::Process';

has 'gpg_bin'   => (is => 'rw', isa => 'Str', default => '/usr/bin/gpg');


sub run {
	my ($self) = @_;
	my $exit;

	while(!$exit) {
		my $msg = $self->recv();
		last unless ($msg);

		if ( $msg->{cmd} eq "list_signatures" ) {
			my $homedir  = $msg->{data}->{homedir};
			my $key_list = $msg->{data}->{list};

			my $data = $self->process_keys($homedir, @$key_list);
#			$self->debug( Dumper[ $msg,   { homedir => $homedir, keys => $key_list, data => $data } ] );

			$self->send("signatures", { homedir => $homedir, keys => $key_list, data => $data } );

			my %seen_keys;
			my @missing;
			foreach my $row (@$data) {
				my $long_key  = uc($row->{uid});
				my $short_key = uc(substr($long_key, -8));

				$seen_keys{$long_key} = 1;
				$seen_keys{$short_key} = 1;

			}

			foreach my $key (@$key_list) {
				my $k = uc($key);
				push @missing, $key unless ( exists $seen_keys{$k} );
			}

			if ( scalar @missing ) {
				$self->error("No signatures found for keys: " . join(', ', @missing) . ". Processed keys: " . join(', ', keys %seen_keys));
				$self->send("signatures_error", { keys => \@missing });
			}
		}
	}
}


sub process_keys {
	my ($self, $homedir, @keys) = @_;

	my @cmd = ($self->gpg_bin, "--homedir", $homedir, "--with-colons", "--fingerprint", "--list-sigs", @keys);

#	$self->debug(join(' ', @cmd));

	open(my $gpg, "-|", @cmd);
	my @data = <$gpg>;
	close $gpg;

	chomp @data;

	my $cur_uid;
	my $fpr;
	my %sigs;
	my @ret;

#	$self->debug(join("\n", @data));

	foreach my $line (@data) {
		my ($type, @parts) = split(/:/, $line);
	#	print "Type: $type\n";	
		if ( $type eq "pub" ) {

			push @ret, { uid => $cur_uid, fingerprint => $fpr, sigs => \%sigs } if ( $cur_uid );
#			handle_sigs($cur_uid, $fpr, \%sigs) if ( $cur_uid )
			%sigs = ();
			undef $fpr;
			$cur_uid = $parts[3];

			print "UID: $cur_uid\n";
		} elsif ( $type eq "fpr" ) {
			$fpr = $parts[8];
		} elsif ( $type eq "sig" ) {
			my $sig = $parts[3];
			$sigs{$sig} = 1;
		}
	}

	push @ret, { uid => $cur_uid, fingerprint => $fpr, sigs => \%sigs } if ( $cur_uid );
#	handle_sigs($cur_uid, $fpr, \%sigs) if ( $cur_uid );


	return \@ret;
}

1;
