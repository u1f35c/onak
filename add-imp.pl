#!/usr/bin/perl

while (<>) {
	/(........)$/;
	print "Attempting to get $1\n";
	$key = `./onak-db2 get $1`;
	open (ONAK, "| ./onak -v add");
	print ONAK $key;
	close ONAK;

	sleep 60;
}
