#!/usr/bin/perl

@keyfile=<>;

$count=0;

while ($count<scalar(@keyfile)) {
	if ($keyfile[$count] =~ /^P/ &&
		$keyfile[$count+1] =~ /^N/ &&
		$keyfile[$count+2] =~ /^S/ &&
		$keyfile[$count+3] =~ /^P/) {
		$count = $count + 3;
	} else {
		print $keyfile[$count++];
	}
}
