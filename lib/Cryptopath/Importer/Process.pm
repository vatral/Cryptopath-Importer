#!/usr/bin/perl -w

package Cryptopath::Importer::Process;
use strict;
use Moose;
use JSON::XS;
use Cryptopath::Importer::Util;
use Carp;

has 'socket' => ( is => 'rw', isa => 'FileHandle' );

sub init {
	my ($self) = @_;
	$self->status("Started");
}

sub run {
	return 0;
}

sub send {
	my ($self, $msg, $data) = @_;
	send_message($self->socket, $msg, $data);
}

sub recv {
	my ($self) = @_;
	return recv_message($self->socket);
}

sub debug {
	my ($self, $msg) = @_;
	$self->send("message", { message => $msg, severity => 0 } );
}

sub info {
	my ($self, $msg) = @_;
	$self->send("message", { message => $msg, severity => 1 } );
}
sub warn {
	my ($self, $msg) = @_;
	$self->send("message", { message => $msg, severity => 2 } );
}
sub error {
	my ($self, $msg) = @_;
	$self->send("message", { message => $msg, severity => 3 } );
}

sub fatal {
	my ($self, $msg) = @_;
	$self->send("message", { message => $msg, severity => 4 } );
	die $msg;
}

sub status {
	my ($self, $status) = @_;
	my $class = ref($self);

	$self->{orig_proc} = $0 unless exists ($self->{orig_proc});

	$0 = $self->{orig_proc} . " [$class] - $status";

	$self->debug("Status: $status");
}

1;
