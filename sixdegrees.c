/*
 * sixdegrees.c - List the size of the six degrees of trust away from a key.
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
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "keydb.h"
#include "keystructs.h"
#include "ll.h"
#include "log.h"
#include "onak-conf.h"
#include "stats.h"

unsigned long countdegree(struct stats_key *have, bool sigs, int maxdegree)
{
	unsigned long     count = 0, curdegree = 0;
	struct ll        *curll, *nextll, *sigll, *tmp;
	struct stats_key *key = NULL;

	++curdegree;

	nextll = NULL;
	curll = lladd(NULL, have);

	while (curll != NULL && curdegree <= maxdegree) {
		if (sigs) {
			sigll = config.dbbackend->cached_getkeysigs(
				((struct stats_key *)
				curll->object)->keyid);
		} else {
			sigll = NULL;
			key = findinhash(((struct stats_key *)
				curll->object)->keyid);
			if (key != NULL) {
				sigll = key->signs;
			}
		}
		while (sigll != NULL) {
			if (((struct stats_key *) sigll->object)->colour==0) {
				/* We've never seen it. Count it, mark it and
					explore its subtree */
				count++;
				((struct stats_key *)sigll->object)->colour = 
					curdegree;
				((struct stats_key *)sigll->object)->parent = 
					((struct stats_key *)
					 curll->object)->keyid;
				nextll=lladd(nextll, sigll->object);
			}
			sigll = sigll->next;
		}
		tmp = curll->next;
		free(curll);
		curll = tmp;
		if (curll == NULL) {
			curll = nextll;
			nextll = NULL;
			++curdegree;
		};
	}
	if (curll != NULL) {
		llfree(curll, NULL);
		curll = NULL;
	}
	if (nextll != NULL) {
		llfree(nextll, NULL);
		nextll = NULL;
	}

	return count;
}

void sixdegrees(uint64_t keyid)
{
	struct stats_key *keyinfo;
	int loop;
	long degree;
	char *uid;

	config.dbbackend->cached_getkeysigs(keyid);

	if ((keyinfo = findinhash(keyid)) == NULL) {
		printf("Couldn't find key 0x%016" PRIX64 ".\n", keyid);
		return;
	}

	uid = config.dbbackend->keyid2uid(keyinfo->keyid);
	printf("Six degrees for 0x%016" PRIX64 " (%s):\n", keyinfo->keyid,
			uid);
	free(uid);
	uid = NULL;

	/*
	 * Cheat. This prefills the ->sign part of all the keys we want to
	 * look at so that we can output that info at the same time as the
	 * signers. However we're assuming that the signers and signees are
	 * reasonably closely related otherwise the info is wildly off - the
	 * only way to get 100% accurate results is to examine every key to see
	 * if it's signed by the key we're looking at.
	 */
	initcolour(false);
	degree = countdegree(keyinfo, true, 7);

	puts("\t\tSigned by\t\tSigns");
	for (loop = 1; loop < 7; loop++) {
		initcolour(false);
		degree = countdegree(keyinfo, true, loop);
		printf("Degree %d:\t%8ld", loop, degree);

		initcolour(false);
		degree = countdegree(keyinfo, false, loop);
		printf("\t\t%8ld\n", degree);
	}
}

int main(int argc, char *argv[])
{
	int optchar;
	char *configfile = NULL;
	uint64_t keyid = 0x2DA8B985;

	while ((optchar = getopt(argc, argv, "c:")) != -1 ) {
		switch (optchar) {
		case 'c':
			configfile = strdup(optarg);
			break;
		}
	}

	if (optind < argc) {
		keyid = strtoll(argv[optind], NULL, 16);
	}

	readconfig(configfile);
	initlogthing("sixdegrees", config.logfile);
	config.dbbackend->initdb(true);
	inithash();
	sixdegrees(config.dbbackend->getfullkeyid(keyid));
	destroyhash();
	config.dbbackend->cleanupdb();
	cleanuplogthing();
	cleanupconfig();

	return 0;
}
