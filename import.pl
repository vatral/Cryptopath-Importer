#!/usr/bin/perl -w
use strict;
use lib 'lib';
use Cryptopath::Importer;

my $importer = Cryptopath::Importer->new();

$importer->init();
$importer->run();

