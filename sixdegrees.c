/*
 * sixdegrees.c - List the size of the six degrees of trust away from a key.
 * 
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2001-2002 Project Purple.
 */

#include <stdio.h>
#include <stdlib.h>

#include "hash.h"
#include "keydb.h"
#include "keystructs.h"
#include "ll.h"
#include "onak-conf.h"
#include "stats.h"

unsigned long countdegree(struct stats_key *have, int maxdegree)
{
	unsigned long count = 0, curdegree = 0;
	struct ll *curll, *nextll, *sigll, *tmp;

	++curdegree;

	nextll = NULL;
	curll = lladd(NULL, have);

	while (curll != NULL && curdegree <= maxdegree) {
		sigll = cached_getkeysigs(((struct stats_key *)
				curll->object)->keyid);
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

	cached_getkeysigs(keyid);

	if ((keyinfo = findinhash(keyid)) == NULL) {
		printf("Couldn't find key 0x%llX.\n", keyid);
		return;
	}

	uid = keyid2uid(keyinfo->keyid);
	printf("Six degrees for 0x%llX (%s):\n", keyinfo->keyid, uid);
	free(uid);
	uid = NULL;

	puts("\t\tSigned by");
	for (loop = 1; loop < 7; loop++) {
		initcolour(false);
		degree = countdegree(keyinfo, loop);
		printf("Degree %d:\t%8ld\n", loop, degree);
		/*
		 * TODO: Used to have keys we signed as well but this takes a
		 * lot of resource and isn't quite appropriate for something
		 * intended to be run on the fly. Given this isn't a CGI at
		 * present perhaps should be readded.
		 */
	}
}

int main(int argc, char *argv[])
{
	uint64_t keyid = 0x5B430367;

	if (argc == 2) {
		keyid = strtoll(argv[1], NULL, 16);
	}

	readconfig();
	initdb();
	inithash();
	sixdegrees(keyid);
	destroyhash();
	cleanupdb();
	cleanupconfig();

	return 0;
}