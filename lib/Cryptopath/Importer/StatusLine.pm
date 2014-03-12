#!/usr/bin/perl -w

package Cryptopath::Importer::StatusLine;

use strict;
use lib 'lib';
use Moose;
use Time::HiRes qw(gettimeofday tv_interval);

has 'min_elapsed_s' => ( is => 'rw', isa => 'Num', default => 0.25 );
has 'min_level'     => ( is => 'rw', isa => 'Int', default => 1 );



sub erase {
	my ($self) = @_;
	my $chars = $self->{erase_chars} // 0;
	print STDERR "\r" . (" " x $chars) . "\r";
}

sub set {
	my ($self, $text, $force) = @_;

	my $elapsed = tv_interval($self->{prev_time} // [0,0]);

	if ( $force || ( $elapsed < $self->min_elapsed_s ) ) {
		# Hasn't been long enough since last call
		# We don't want to bog down the CPU with status updates
		return;
	}
	
	$self->erase;
	$self->{erase_chars} = length($text);
	$self->{prev_time} = [gettimeofday];
	$self->{last_text} = $text;

	print STDERR $text;
}

sub message {
	my ($self, $level, $msg) = @_;

	return if ( $level > $self->min_level );

	$self->erase();
	print STDERR "L${level} $msg\n";
	$self->set( $self->{last_text} // "", 1 );
}


1;

