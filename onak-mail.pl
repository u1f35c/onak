#!/usr/bin/perl -w

#
# onak-mail.pl - Mail processing interface for onak, an OpenPGP Keyserver.
#
# Written by Jonathan McDowell <noodles@earth.li>
# Copyright 2002 Project Purple
# Released under the GPL.
#

use strict;
use IPC::Open3;

#
# submitupdate
#
# Takes an armored OpenPGP stream and submits it to the keyserver. Returns the
# difference between what we just added and what we had before (ie the least
# data need to get from what we had to what we have).
#
sub submitupdate {
	my @data = @_;
	my (@errors, @mergedata);

	open3(\*MERGEIN, \*MERGEOUT, \*MERGEERR, "/home/noodles/onak-0.0.3/onak", "add");

	print MERGEIN @data;
	close MERGEIN;
	@errors = <MERGEERR>;
	@mergedata = <MERGEOUT>;

	open (LOG, ">>/home/noodles/onak-0.0.3/keyadd.log");
	print LOG @errors;
	close LOG;

	return @mergedata;
}

my ($inheader, %syncsites, $subject, $from, $replyto, @body, @syncmail);

$inheader = 1;
$subject = "";

while (<>) {
	if ($inheader) {
		if (/^Subject:\s*(.*)\s*$/i) {
			$subject = $1;
		} elsif (/^X-KeyServer-Sent:\s*(.*)\s*$/i) {
			$syncsites{$1} = 1;
		} elsif (/^From:\s*(.*)\s*$/i) {
			$from = $1;
		} elsif (/^Reply-To:\s*(.*)\s*$/i) {
			$replyto = $1;
		} elsif (/^$/) {
			$inheader = 0;
		}
	}
	if (!$inheader) {
		push @body, $_;
	}
}

# HELP, ADD, INCREMENTAL, VERBOSE INDEX <keyid>, INDEX <keyid>, GET <keyid>,
# LAST <days>

if ($subject =~ /^INCREMENTAL$/i) {
	submitupdate(@body);
}
