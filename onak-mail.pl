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

my %config;

#
# readconfig
#
# Reads in our config file. Ignores any command it doesn't understand rather
# than having to list all the ones that are of no interest to us.
#
sub readconfig {

	open(CONFIG, "/home/noodles/projects/onak/onak.conf") or
		die "Can't read config file: $!";
	
	while (<CONFIG>) {
		if (/^#/ or /^$/) {
			# Ignore; comment line.
		} elsif (/^this_site (.*)/) {
			$config{'thissite'} = $1;
		} elsif (/^maintainer_email (.*)/) {
			$config{'adminemail'} = $1;
		} elsif (/^mail_delivery_client (.*)/) {
			$config{'mta'} = $1;
		} elsif (/^syncsite (.*)/) {
			push @{$config{'syncsites'}}, $1;
		}
	}

	close(CONFIG);

	return;
}

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

	open3(\*MERGEIN, \*MERGEOUT, \*MERGEERR,
		"/home/noodles/onak-0.0.3/onak", "-u", "add");

	print MERGEIN @data;
	close MERGEIN;
	@errors = <MERGEERR>;
	@mergedata = <MERGEOUT>;

	open (LOG, ">>/home/noodles/onak-0.0.3/keyadd.log");
	print LOG "[".localtime(time)."] ", @errors;
	close LOG;

	return @mergedata;
}

my ($inheader, %seenby, $subject, $from, $replyto, @body, @syncmail);

$inheader = 1;
$subject = "";
&readconfig;

while (<>) {
	if ($inheader) {
		if (/^Subject:\s*(.*)\s*$/i) {
			$subject = $1;
		} elsif (/^X-KeyServer-Sent:\s*(.*)\s*$/i) {
			$seenby{$1} = 1;
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
	my $site;
	my $count;
	my $i;
	my @newupdate = submitupdate(@body);

	$count = 0;
	foreach $i (@{$config{'syncsites'}}) {
		if (! defined($seenby{$i})) {
			$count++;
		}
	}

	open (LOG, ">>/home/noodles/logs/keyadd.log");
	print LOG "[".localtime(time)."] Syncing with $count sites.\n";
	close LOG;

	if ($newupdate[0] eq '') {
		open (LOG, ">>/home/noodles/logs/keyadd.log");
		print LOG "[".localtime(time)."] Nothing to sync.\n";
		close LOG;
		$count = 0;
	}

	if ($count > 0) {
		open(MAIL, "|$config{mta}");
		print MAIL "From: $config{adminemail}\n";
		print MAIL "To: ";
		foreach $i (@{$config{'syncsites'}}) {
			if (! defined($seenby{$i})) {
				print MAIL "$i";
				$count--;
				if ($count > 0) {
					print MAIL ", ";
				}
			}
		}
		print MAIL "\n";
		print MAIL "Subject: incremental\n";
		foreach $site (keys %seenby) {
			print MAIL "X-KeyServer-Sent: $site\n";
		}
		print MAIL "X-KeyServer-Sent: $config{thissite}\n";
		print MAIL "Precedence: list\n";
		print MAIL "MIME-Version: 1.0\n";
		print MAIL "Content-Type: application/pgp-keys\n";
		print MAIL "\n";
		print @newupdate;
		close MAIL;
	}
}
