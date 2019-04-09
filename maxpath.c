/*
 * maxpath.c - Find the longest trust path in the key database.
 *
 * Copyright 2001-2002 Jonathan McDowell <noodles@earth.li>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "keydb.h"
#include "ll.h"
#include "log.h"
#include "onak-conf.h"
#include "stats.h"

void findmaxpath(struct onak_dbctx *dbctx, unsigned long max)
{
	struct stats_key *from, *to, *tmp;
	struct ll *curkey;
	unsigned long distance, loop;

	distance = 0;
	from = to = tmp = NULL;

	/*
	 * My (noodles@earth.li, RSA) key is in the strongly connected set of
	 * keys, so we use it as a suitable starting seed.
	 */
	dbctx->cached_getkeysigs(dbctx, 0x94FA372B2DA8B985);

	/*
	 * Loop through the hash examining each key present and finding the
	 * furthest key from it. If it's further than our current max then
	 * store it as our new max and print out the fact we've found a new
	 * max.
	 */
	for (loop = 0; (loop < HASHSIZE) && (distance < max); loop++) {
		curkey = gethashtableentry(loop);
		while (curkey != NULL && distance < max) {
			dbctx->cached_getkeysigs(dbctx,
					((struct stats_key *)
					curkey->object)->keyid);
			initcolour(false);
			tmp = furthestkey(dbctx, (struct stats_key *)
						curkey->object);
			if (tmp->colour > distance) {
				from = (struct stats_key *)curkey->object;
				to = tmp;
				distance = to->colour;
				printf("Current max path (#%ld) is from %"
						PRIX64 " to %" PRIX64 
						" (%ld steps)\n", 
						loop,
						from->keyid,
						to->keyid,
						distance);
			}
			curkey=curkey->next;
		}
	}
	printf("Max path is from %" PRIX64 " to %" PRIX64 " (%ld steps)\n",
			from->keyid,
			to->keyid,
			distance);
	dofindpath(dbctx, to->keyid, from->keyid, false, 1);
}

int main(int argc, char *argv[])
{
	int optchar;
	char *configfile = NULL;
	struct onak_dbctx *dbctx;

	while ((optchar = getopt(argc, argv, "c:")) != -1 ) {
		switch (optchar) {
		case 'c':
			if (configfile != NULL) {
				free(configfile);
			}
			configfile = strdup(optarg);
			break;
		}
	}

	readconfig(configfile);
	free(configfile);
	initlogthing("maxpath", config.logfile);
	dbctx = config.dbinit(config.backend, true);
	if (dbctx != NULL) {
		inithash();
		findmaxpath(dbctx, 30);
		printf("--------\n");
		findmaxpath(dbctx, 30);
		destroyhash();
		dbctx->cleanupdb(dbctx);
	} else {
		fprintf(stderr, "Couldn't initialize key database.\n");
	}
	cleanuplogthing();
	cleanupconfig();
	
	return EXIT_SUCCESS;
}
