/*
	gpgstats.h - Program to produce stats on a GPG keyring.
	Written by Jonathan McDowell <noodles@earth.li>.

	19/02/2000 - Started writing (sort of).
*/

#ifndef __GPGSTATS_H_
#define __GPGSTATS_H_

#define VERSION "0.0.2"

#include "ll.h"

/* Structure to hold a key's info */
struct key {
	unsigned long keyid;
	char *name;
	struct ll *sigs;
	struct ll *signs;
	struct ll *pi;
	int colour;
	int selfsigned;
	int revoked;
};

void readkeys();
long checkselfsig();
int main(int argc, char *argv[]);

#endif
