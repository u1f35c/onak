/*
 * maxpath.c - Find the longest trust path in the key database.
 * 
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2001-2002 Project Purple.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stats.h"
#include "hash.h"
#include "keydb.h"
#include "ll.h"
#include "log.h"
#include "onak-conf.h"
#include "stats.h"

void findmaxpath(unsigned long max)
{
	struct stats_key *from, *to, *tmp;
	struct ll *curkey;
	unsigned long distance, loop;

	distance = 0;
	from = to = tmp = NULL;

	/*
	 * My (noodles@earth.li, DSA) key is in the strongly connected set of
	 * keys, so we use it as a suitable starting seed.
	 */
	config.dbbackend->cached_getkeysigs(0xF1BD4BE45B430367);

	/*
	 * Loop through the hash examining each key present and finding the
	 * furthest key from it. If it's further than our current max then
	 * store it as our new max and print out the fact we've found a new
	 * max.
	 */
	for (loop = 0; (loop < HASHSIZE) && (distance < max); loop++) {
		curkey = gethashtableentry(loop);
		while (curkey != NULL && distance < max) {
			config.dbbackend->cached_getkeysigs(
					((struct stats_key *)
					curkey->object)->keyid);
			initcolour(false);
			tmp = furthestkey((struct stats_key *)
						curkey->object);
			if (tmp->colour > distance) {
				from = (struct stats_key *)curkey->object;
				to = tmp;
				distance = to->colour;
				printf("Current max path (#%ld) is from %llX"
						" to %llX (%ld steps)\n", 
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
	dofindpath(to->keyid, from->keyid, false, 1);
}

int main(int argc, char *argv[])
{
	readconfig(NULL);
	initlogthing("maxpath", config.logfile);
	config.dbbackend->initdb(true);
	inithash();
	findmaxpath(30);
	printf("--------\n");
	findmaxpath(30);
	destroyhash();
	config.dbbackend->cleanupdb();
	cleanuplogthing();
	cleanupconfig();
	
	return EXIT_SUCCESS;
}
