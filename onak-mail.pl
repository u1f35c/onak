#!/usr/bin/perl -w
#
# onak-mail.pl - Mail processing interface for onak, an OpenPGP Keyserver.
#
# Written by Jonathan McDowell <noodles@earth.li>
# Copyright 2002 Project Purple
# Released under the GPL.
#
# $Id: onak-mail.pl,v 1.9 2004/01/04 18:48:37 noodles Exp $
#

use strict;
use Fcntl ':flock';
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
		} elsif (/^logfile (.*)/) {
			$config{'logfile'} = $1;
		} elsif (/^maintainer_email (.*)/) {
			$config{'adminemail'} = $1;
		} elsif (/^mail_delivery_client (.*)/) {
			$config{'mta'} = $1;
		} elsif (/^pks_bin_dir (.*)/) {
			$config{'pks_bin_dir'} = $1;
		} elsif (/^db_dir (.*)/) {
			$config{'db_dir'} = $1;
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

	open(LOCKFILE, '>'.$config{'db_dir'}.'/onak-mail.lck');
	flock(LOCKFILE, LOCK_EX);
	print LOCKFILE "$$";

	open3(\*MERGEIN, \*MERGEOUT, \*MERGEERR,
		$config{'pks_bin_dir'}."/onak", "-u", "add");

	print MERGEIN @data;
	close MERGEIN;
	@mergedata = <MERGEOUT>;
	close MERGEOUT;
	@errors = <MERGEERR>;
	close MERGEERR;

	flock(LOCKFILE, LOCK_UN);
	close(LOCKFILE);

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
if (! defined($replyto)) {
	$replyto = $from;
}

# HELP, ADD, INCREMENTAL, VERBOSE INDEX <keyid>, INDEX <keyid>, GET <keyid>,
# LAST <days>

if ($subject =~ /^INCREMENTAL$/i) {
	my $site;
	my $count;
	my $i;
	my @newupdate = submitupdate(@body);
	my @time;

	$count = 0;
	foreach $i (@{$config{'syncsites'}}) {
		if (! defined($seenby{$i})) {
			$count++;
		}
	}

	open (LOG, ">>$config{'logfile'}");
	@time = localtime(time);
	print LOG "[";
	print LOG sprintf "%02d/%02d/%04d %02d:%02d:%02d",
		$time[3], $time[4] + 1, $time[5] + 1900,
		$time[2], $time[1], $time[0];
	print LOG "] onak-mail[$$]: Syncing with $count sites.\n";
	close LOG;

	if ((! defined($newupdate[0])) || $newupdate[0] eq '') {
		open (LOG, ">>$config{'logfile'}");
		print LOG "[";
		print LOG sprintf "%02d/%02d/%04d %02d:%02d:%02d",
			$time[3], $time[4] + 1, $time[5] + 1900,
			$time[2], $time[1], $time[0];
		print LOG "] onak-mail[$$]: Nothing to sync.\n";
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
		print MAIL @newupdate;
		close MAIL;
	}
} elsif ($subject =~ /^(VERBOSE )?INDEX (.*)$/i) {
	my (@indexdata, $command);

	$command = "index";
	if (defined($1)) {
		$command = "vindex";
	}

	open3(\*INDEXIN, \*INDEXOUT, \*INDEXERR,
		$config{'pks_bin_dir'}."/onak", $command, "$2");
	close INDEXIN;
	@indexdata = <INDEXOUT>;
	close INDEXOUT;
	close INDEXERR;

	open(MAIL, "|$config{mta}");
	print MAIL "From: $config{adminemail}\n";
	print MAIL "To: $replyto\n";
	print MAIL "Subject: Reply to INDEX $2\n";
	print MAIL "Precedence: list\n";
	print MAIL "MIME-Version: 1.0\n";
	print MAIL "Content-Type: text/plain\n";
	print MAIL "\n";
	print MAIL "Below follows the reply to your recent keyserver query:\n";
	print MAIL "\n";
	print MAIL @indexdata;
	close MAIL;
}
