/*
	gpgstats.c - Program to produce stats on a GPG keyring.
	Written by Jonathan McDowell <noodles@earth.li>.

	19/02/2000 - Started writing (sort of).
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stats.h"
#include "hash.h"
#include "keydb.h"
#include "ll.h"
#include "stats.h"

void findmaxpath(unsigned long max)
{
	struct stats_key *from, *to, *tmp;
	struct ll *curkey;
	unsigned long distance, loop;

	distance = 0;
	from = to = tmp = NULL;
	hash_getkeysigs(0xF1BD4BE45B430367);

	for (loop = 0; (loop < HASHSIZE) && (distance < max); loop++) {
		curkey = gethashtableentry(loop);
		while (curkey != NULL && distance < max) {
			hash_getkeysigs(((struct stats_key *)
					curkey->object)->keyid);
			initcolour(false);
			tmp = furthestkey((struct stats_key *)
						curkey->object);
			if (tmp->colour > distance) {
				from = (struct stats_key *)curkey->object;
				to = tmp;
				distance = to->colour;
				printf("Current max path (#%ld) is from %llX to %llX (%ld steps)\n", 
						loop,
						from->keyid,
						to->keyid,
						distance);
			}
			curkey=curkey->next;
		}
	}
	printf("Max path is from %llX to %llX (%ld steps)\n",
			from->keyid,
			to->keyid,
			distance);
	dofindpath(to->keyid, from->keyid, false);
}

int main(int argc, char *argv[])
{
	initdb();
	inithash();
	findmaxpath(30);
	printf("--------\n");
	findmaxpath(30);
	destroyhash();
	cleanupdb();
	
	return EXIT_SUCCESS;
}
