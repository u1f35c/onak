#!/usr/bin/perl
#
# $Id: add-imp.pl,v 1.2 2003/06/04 20:57:06 noodles Exp $
#

while (<>) {
	/(........)$/;
	print "Attempting to get $1\n";
	$key = `./onak-db2 get $1`;
	open (ONAK, "| ./onak -v add");
	print ONAK $key;
	close ONAK;

	sleep 60;
}
