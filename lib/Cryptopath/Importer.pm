#!/usr/bin/perl -w

package Cryptopath::Importer;

use strict;
use lib 'lib';
use Moose;
use BerkeleyDB;
use File::Temp qw( tempdir );
use Socket;
use IO::Select;
use Cryptopath::Importer::Util;
use Data::Dumper qw(Dumper);
use POSIX ":sys_wait_h";


has 'base_class' => (  is => 'rw', isa => 'Str', default => "Cryptopath::Importer::Process" );

sub init {
	my ($self) = @_;

	$self->{loaded_packages} = {};
	$self->{proc_bypid} = {};
	$self->{proc_bycls} = {};


	$SIG{CHLD} = sub {
		while ((my $pid = waitpid(-1, WNOHANG)) > 0) {
			if ( exists $self->{proc_bypid}{$pid} ) {
				$self->{proc_bypid}{$pid}->{status} = "dead";
			}
		}
	};

	$self->_create_process( "Cryptopath::Importer::Process::HKP" );
	$self->_create_process( "Cryptopath::Importer::Process::ListSignatures" );
	$self->_create_process( "Cryptopath::Importer::Process::Postgres" );

}


sub run {
	my ($self) = @_;

	my $terminate;


	while(!$terminate && scalar keys %{ $self->{proc_bypid} }) {
		my $want_read   = IO::Select->new();
		my $want_write  = IO::Select->new();
		my $want_except = IO::Select->new();

		my @dead_procs;

		foreach my $pid ( keys %{ $self->{proc_bypid} } ) {
			my $p = $self->{proc_bypid}{$pid};

			if ( $p->{status} eq "dead" ) {
				push @dead_procs, $pid;
			}

			if ( exists $p->{sock} ) {
				$want_read->add( $p->{sock} );
			}
		}

		foreach my $pid ( @dead_procs ) {
			$self->_message( $self, 4, "Process with pid $pid and class " . $self->{proc_bypid}{$pid}->{class} . " terminated");
			$self->_delete_process($pid);
		}
		
		my ($can_read, $can_write, $has_exception) = 
			IO::Select::select( $want_read, $want_write, $want_except );

		foreach my $handle ( @$can_read ) {
			#print "Can read: $handle\n";

			my $proc = $self->_find_process($handle);
			my $msg  = recv_message($handle);

			if (!$msg) {
				$self->_message( $proc,  3, "Process with pid " . $proc->{pid}  .  " closed the connection");
				delete $proc->{sock};
				next;
			}

			my $cmd  = $msg->{cmd};
			my $data = $msg->{data};





			if ( $cmd eq "message" ) {
				$self->_message( $proc, $data->{severity}, $data->{message});
			}

	#		print "Message: " . Dumper([$msg]) . "\n";
		}

	}


	sleep 10;


	$self->_stop_all();


	exit(1);



	my $dir       = "/srv/sks/dump/KDB";
	my $keyserver = "hkp://localhost:11371";
	my $homedir   = tempdir( CLEANUP => 1 );


	my %keys;
	my $db = tie %keys, 'BerkeleyDB::Btree', -Filename => "$dir/keyid", -Flags => DB_RDONLY;
	my @keys;



	while( my ($key, $val) = each %keys ) {

		my $k = unpack("H*", $key);
		my $v = unpack("H*", $val);
		print "$k: $v\n";

		push @keys, $k;

		if ( scalar @keys >= 10 ) {
			#unlink($keyring);


	#		my @missing;
	#		@missing = grep { !key_exists($_) } @keys;
	#
	#
	#		fetch_keys(@missing);
	#		process_keys(@missing);
	#		@keys = ();
	#
	#	#idie;
		}
	}

}


sub _create_process {
	my ($self, $class) = @_;
	my $instance = $self->_instantiate($class);


	my ($parent_sock, $child_sock);
	socketpair($parent_sock, $child_sock, AF_UNIX, SOCK_STREAM, PF_UNSPEC);

	my $pid = fork();
	if ( $pid ) {
		print STDERR "Starting process $pid for $class\n";
		close $child_sock;
		my $proc_info = { class => $class, sock => $parent_sock, pid => $pid, status => 'alive' };

		$self->{proc_bypid}{$pid} = $proc_info;
		$self->{proc_bycls}{$class} = {} unless ( exists $self->{proc_bycls}{$class});
		$self->{proc_bycls}{$class}->{$pid} = $proc_info;
	} elsif ( $pid == 0 ) {
		my $retval = 101;

		eval {
			$SIG{CHLD} = 'IGNORE';
			close $parent_sock;


			my $instance = $self->_instantiate($class);
			my $retval;

			$instance->socket( $child_sock );
			$instance->init();

			eval {
				$retval = $instance->run();
			};
			if ( $@ ) {
				$instance->error("Process died with message: $@");
				$retval = 100;
			}
		};
		if ( $@ ) {
			print STDERR "Error in pid $$: $@";
		}

		shutdown $child_sock, 2;
		exit($retval);

	} else {
		die "Fork failed: $!";
	}

}

sub _stop_process {
	my ($self, $pid) = @_;
	if (!exists $self->{proc_bypid}{$pid}) {
		warn "Process $pid not found";
		return;
	}

	my $p = $self->{proc_bypid}{$pid};
	$p->{stop_request_time} = time
		unless exists $p->{stop_request_time};

	if ( time -  $p->{stop_request_time} < 3 ) {
		if ( ! $p->{term_sent} ) {
			kill 'TERM', $pid;
			$p->{term_sent} = 1;
		}
	} else {
		kill 'KILL', $pid;
		$self->_delete_process($pid);
	}
		
}

sub _delete_process {
	my ( $self, $pid ) = @_;

	delete $self->{proc_bypid}{$pid};

	foreach my $class (keys %{ $self->{proc_bycls} }) {
		delete $self->{proc_bycls}{$class}->{$pid};
	}

}

sub _find_process {
	my ($self, $socket) = @_;

	foreach my $pid ( keys %{ $self->{proc_bypid} } ) {
		if ( $self->{proc_bypid}{$pid}->{sock} == $socket ) {
			return $self->{proc_bypid}{$pid};
		}
	}

	die "Failed to find process with socket $socket, something is wrong";
}



sub _stop_all {
	my ($self) = @_;

	while( scalar keys %{ $self->{proc_bypid} } ) {
		foreach my $pid ( keys %{ $self->{proc_bypid} } ) {
			$self->_stop_process($pid);
		}

		sleep 1;
	}
}

sub _instantiate {
	my ($self, $class) = @_;
	my $create = "";

	if (!$self->{loaded_packages}{$class}) {
		$create = "require $class;\n";
	}

	$self->{loaded_packages}{$class} = 1;
	
	$create .= "require $class; $class->new();";

	my $instance = eval($create);

	die "Failed to create $class: $@" if (!$instance);
	die "$class does not inherit from $self->{base_class}" unless ($instance->isa($self->{base_class}));

	return $instance;
}

sub _message {
	my ($self, $class, $severity, $msg) = @_;

	my $cls;

	if ( ref($class) eq "HASH" ) {
		# Process struct passed
		$cls = $class->{class};
	} elsif ( ref($class) ) {
		# Object passed
		$cls = ref($class);
	} else {
		# String
		$cls = $class;
	}

	print STDERR "L$severity [$cls] $msg\n";
}


1;
