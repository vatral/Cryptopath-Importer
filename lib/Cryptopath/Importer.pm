#!/usr/bin/perl -w

package Cryptopath::Importer;

use strict;
use lib 'lib';
use Moose;
use BerkeleyDB;
use File::Temp qw( tempdir );
use Socket;
use IO::Select;
use Cryptopath::Importer::Util qw(enqueue_message send_message recv_message);
use Data::Dumper qw(Dumper);
use POSIX ":sys_wait_h";
use Time::HiRes qw(gettimeofday tv_interval);
use File::Path qw(remove_tree);

has 'base_class'       => ( is => 'rw', isa => 'Str', default => "Cryptopath::Importer::Process" ); # Base class for all processes
has 'class_prefix'     => ( is => 'rw', isa => 'Str', default => 'Cryptopath::Importer::Process' ); # Prefix for short class names
has 'max_queue_length' => ( is => 'rw', isa => 'Int', default => 4 );


sub init {
	my ($self) = @_;

	$self->{loaded_packages} = {};
	$self->{proc_bypid} = {};
	$self->{proc_bycls} = {};
	$self->{sigint} = 0;


	$SIG{CHLD} = sub {
		while ((my $pid = waitpid(-1, WNOHANG)) > 0) {
			if ( exists $self->{proc_bypid}{$pid} ) {
				$self->{proc_bypid}{$pid}->{status} = "dead";
			}
		}
	};

	$SIG{INT} = sub {
		$self->{sigint}++;
	};

	$self->_create_process( "Cryptopath::Importer::Process::KeyLister" );
	$self->_create_process( "Cryptopath::Importer::Process::KeyChecker" );
	$self->_create_process( "Cryptopath::Importer::Process::HKP" );
	$self->_create_process( "Cryptopath::Importer::Process::ListSignatures" );
	$self->_create_process( "Cryptopath::Importer::Process::Postgres" );

}


sub run {
	my ($self) = @_;

	my $abort;

	$self->{raw_key_ids_buf}  = [];  # Known IDs
	$self->{good_key_ids_buf} = []; # Verified not to exist in DB
	$self->{recv_key_ids_buf} = []; # Received from keyserver
	$self->{signatures_buf}   = []; # Signatures

	$self->{stat_keys_started}    = 0;
	$self->{stat_keys_added}      = 0;
	$self->{stat_keys_existing}   = 0;
	$self->{stat_keys_sign_error} = 0;

	while(!$abort && scalar keys %{ $self->{proc_bypid} }) {
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

			if (scalar @{ $p->{commands} }) {
				$want_write->add( $p->{sock} );
			}
		}

		foreach my $pid ( @dead_procs ) {
			$self->_message( $self, 4, "Process with pid $pid and class " . $self->{proc_bypid}{$pid}->{class} . " terminated");
			$self->_delete_process($pid);
		}
		
		my ($can_read, $can_write, $has_exception) = 
			IO::Select::select( $want_read, $want_write, $want_except );

		if ( $self->{sigint} == 1 ) {
			$self->_message( $self, 4, "SIGINT received, stopping");
			$self->_stop_all();
		} elsif ( $self->{sigint} > 1 ) {
			$abort = 1;
		}

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
			} elsif ( $cmd eq "keys" ) {
				push @{ $self->{raw_key_ids_buf} }, @{ $data->{list} };
				$self->{stat_keys_started} += scalar @{ $data->{list} };

#				$self->_message( $self, 1, "Keys received");
			} elsif ( $cmd eq "verified_keys" ) {
				push @{ $self->{good_key_ids_buf} }, @{ $data->{list} };
				#$self->_message( $self, 1, "Good keys received, first: " . $data->{list}->[0]);
			} elsif ( $cmd eq "existing_keys" ) {
				$self->{stat_keys_existing} += scalar @{ $data->{list} };
			} elsif ( $cmd eq "keys_received" ) {
				push @{ $self->{recv_key_ids_buf} }, $data;
			} elsif ( $cmd eq "signatures" ) {

				foreach my $keysigs( @{$data->{data}} ) {
					push @{ $self->{signatures_buf} }, $keysigs;
				}

				remove_tree( $data->{homedir} );
			} elsif ( $cmd eq "signatures_error" ) {
				$self->{stat_keys_sign_error} += scalar @{ $data->{keys} };
			} elsif ( $cmd eq "key_added" ) {
				$self->{stat_keys_added}++;
			} else {
				$self->_message( $self, 3, "Unrecognized message: $cmd");
			}

	#		print "Message: " . Dumper([$msg]) . "\n";
		}


		foreach my $handle( @$can_write ) {
			my $proc = $self->_find_process($handle);

			if ( scalar @{ $proc->{commands} } ) {
				my $cmd = shift @{ $proc->{commands} };
				send_message( $handle, $cmd );
			}
		}

		if ( scalar @{ $self->{good_key_ids_buf} } < 32 
		  && scalar @{ $self->{raw_key_ids_buf} } < 128 &&
		    !$self->_is_busy('KeyLister')) {
			$self->_send_cmd("KeyLister", "get_keys", { count => 16 } );
		}

		if ( scalar @{ $self->{raw_key_ids_buf} } > 0 && 
		  ! $self->_is_busy('KeyChecker') ) {
			$self->_send_cmd("KeyChecker", "check_keys", { list => $self->{raw_key_ids_buf} } );
			$self->{raw_key_ids_buf} = [];
		}

		if ( scalar @{ $self->{good_key_ids_buf} } > 0 &&
		  ! $self->_is_busy('HKP')) {
			my @ids = splice(@{$self->{good_key_ids_buf} }, 0, 10);
			my $homedir = tempdir( cleanup => 0 );

			$self->_send_cmd("HKP", "fetch_keys", { homedir => $homedir, list => \@ids });
		}

		if ( scalar @{ $self->{recv_key_ids_buf} } > 0 &&
		  ! $self->_is_busy('ListSignatures')) {
			my $entry = shift @{ $self->{recv_key_ids_buf} };
			$self->_send_cmd("ListSignatures", "list_signatures", $entry);
		}

		if ( scalar @{ $self->{signatures_buf} } > 0 &&
		  ! $self->_is_busy('Postgres')) {
			my $entry = shift $self->{signatures_buf};
			$self->_send_cmd('Postgres', "add_key", $entry);
		}


		$self->_status();
	}


	sleep 10;


	$self->_stop_all();


	exit(1);

}

sub _erase_status {
	my ($self) = @_;
	my $chars = $self->{erase_chars} // 0;
	print STDERR "\r" . (" " x $chars) . "\r";
}

sub _status {
	my ($self, $force) = @_;
	my $txt;

	if ( $force || ( exists $self->{prev_time} && tv_interval($self->{prev_time}) < 0.25 ) ) {
		# Hasn't been long enough since last call
		# We don't want to bog down the CPU with status updates
		return;
	}
	
	$txt  = "Buf: " . scalar @{ $self->{raw_key_ids_buf}};
	$txt .= "/"     . scalar @{ $self->{good_key_ids_buf}};
	$txt .= "/"     . scalar @{ $self->{recv_key_ids_buf}};
	$txt .= "/"     . scalar @{ $self->{signatures_buf}};

	$txt .= ", keys loaded: " . $self->{stat_keys_started};
	$txt .= ", added: " . $self->{stat_keys_added};
	$txt .= ", existing: " . $self->{stat_keys_existing};
	$txt .= ", no signatures: " . $self->{stat_keys_sign_error};

	$self->_erase_status();
	$self->{erase_chars} = length($txt);
	$self->{prev_time} = [gettimeofday];

	print STDERR $txt;
}

sub _get_proc {
	my ($self, $proc) = @_;
	my $p;

	if ( ref($proc) ) {
		# Send to indicated process
		$p = $proc;
	} else {
		# Send to class
		if (!exists $self->{proc_bycls}{$proc}) {
			$proc = $self->base_class . "::$proc";
		}

		die "Class not found" unless (exists $self->{proc_bycls}{$proc});

		my $min_cmds = 2^31;

		foreach my $pid ( keys %{ $self->{proc_bycls}->{$proc} }) {
			my $count = scalar @{ $self->{proc_bypid}{$pid}{commands} };
			if ( $count < $min_cmds ) {
				$min_cmds = $count;
				$p        = $self->{proc_bypid}{$pid};
			}
		}

		die "No processes in class $proc" unless ($p);
	}

	return $p;
}

sub _send_cmd {
	my ($self, $proc, $cmd, $data) = @_;

	my $p = $self->_get_proc($proc);
	enqueue_message($p->{commands}, $cmd, $data);
}

sub _is_busy {
	my ($self, $proc) = @_;
	my $p = $self->_get_proc($proc);

	return ( scalar @{ $p->{commands} } >= $self->max_queue_length );
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

		my $proc_info = {
			class     => $class,
			sock      => $parent_sock,
			pid       => $pid,
			status    => 'alive',
			commands  => []
		};

		$self->{proc_bypid}{$pid} = $proc_info;
		$self->{proc_bycls}{$class} = {} unless ( exists $self->{proc_bycls}{$class});
		$self->{proc_bycls}{$class}->{$pid} = $proc_info;
	} elsif ( $pid == 0 ) {
		my $retval = 101;

		eval {
			$SIG{CHLD} = 'IGNORE';
			close $parent_sock;
			close STDOUT;
			close STDERR;
			open 'STDOUT', '>', '/dev/null';
			open 'STDERR', '>', '/dev/null';

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
		next unless ( exists $self->{proc_bypid}{$pid}->{sock} );

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

	$self->_erase_status();
	print STDERR "L$severity [$cls] $msg\n";
	$self->_status(1);

}


1;
