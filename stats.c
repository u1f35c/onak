/*
 * stats.c - various routines to do stats on the key graph
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2000-2002 Project Purple
 *
 * $Id: stats.c,v 1.11 2003/06/04 22:32:56 noodles Exp $
 */

#include <stdio.h>
#include <stdlib.h>

#include "getcgi.h"
#include "hash.h"
#include "keydb.h"
#include "ll.h"
#include "stats.h"

/**
 *	initcolour - Clear the key graph ready for use.
 *	@parent: Do we want to clear the parent pointers too?
 *
 *	Clears the parent and colour information on all elements in the key
 *	graph.
 */
void initcolour(bool parent)
{
	unsigned long loop;
	struct ll *curkey;

	/*
	 * Init the colour/parent values. We get each entry list from the hash
	 * table and walk along it, zeroing the values.
	 */
	for (loop = 0; loop < HASHSIZE; loop++) {
		curkey = gethashtableentry(loop);
		while (curkey != NULL) {
			((struct stats_key *)curkey->object)->colour = 0;
			if (parent) {
				((struct stats_key *)curkey->object)->parent =
					0;
			}
			curkey = curkey->next;
		}
	}
}

/**
 *	findpath - Given 2 keys finds a path between them.
 *	@have: The key we have.
 *	@want: The key we want to get to.
 *
 *	This does a breadth first search on the key tree, starting with the
 *	key we have. It returns as soon as a path is found or when we run out
 *	of keys; whichever comes sooner.
 */
unsigned long findpath(struct stats_key *have, struct stats_key *want)
{
	struct ll *keys = NULL;
	struct ll *oldkeys = NULL;
	struct ll *sigs = NULL;
	struct ll *nextkeys = NULL;
	long curdegree = 0;
	long count = 0;
	
	curdegree = 1;
	keys = lladd(NULL, want);
	oldkeys = keys;

	while (keys != NULL && have->colour == 0) {
		sigs = cached_getkeysigs(((struct stats_key *)
					keys->object)->keyid);
		while (sigs != NULL && have->colour == 0) {
			/*
			 * Check if we've seen this key before and if not mark
			 * it and add its sigs to the list we want to look at.
			 */
			if (!((struct stats_key *)sigs->object)->disabled &&
			    ((struct stats_key *)sigs->object)->colour == 0) {
				count++;
				((struct stats_key *)sigs->object)->colour =
					curdegree;
				((struct stats_key *)sigs->object)->parent =
					((struct stats_key *)
					 keys->object)->keyid;
				nextkeys = lladd(nextkeys, sigs->object);
			}
			sigs = sigs->next;
		}
		keys = keys->next;
		if (keys == NULL) {
			keys = nextkeys;
			llfree(oldkeys, NULL);
			oldkeys = keys;
			nextkeys = NULL;
			curdegree++;
		}
	}
	if (oldkeys != NULL) {
		llfree(oldkeys, NULL);
		oldkeys = NULL;
	}
	if (nextkeys != NULL) {
		llfree(nextkeys, NULL);
		nextkeys = NULL;
	}

	return count;
}

/**
 *	dofindpath - Given 2 keys displays a path between them.
 *	@have: The key we have.
 *	@want: The key we want to get to.
 *	@html: Should we output in html.
 *	@count: How many paths we should look for.
 *
 *	This does a breadth first search on the key tree, starting with the
 *	key we have. It returns as soon as a path is found or when we run out
 *	of keys; whichever comes sooner.
 */
void dofindpath(uint64_t have, uint64_t want, bool html, int count)
{
	struct stats_key *keyinfoa, *keyinfob, *curkey;
	uint64_t fullhave, fullwant;
	int rec;
	int pathnum;
	char *uid;

	fullhave = getfullkeyid(have);
	fullwant = getfullkeyid(want);

	/*
	 * Make sure the keys we have and want are in the cache.
	 */
	cached_getkeysigs(fullhave);
	cached_getkeysigs(fullwant);

	if ((keyinfoa = findinhash(fullhave)) == NULL) {
		printf("Couldn't find key 0x%llX.\n", have);
		return;
	}
	if ((keyinfob = findinhash(fullwant)) == NULL) {
		printf("Couldn't find key 0x%llX.\n", want);
		return;
	}

	pathnum = 0;
	
	while (pathnum < count) {
		/*
		 * Fill the tree info up.
		 */
		initcolour(true);
		rec = findpath(keyinfoa, keyinfob);
		keyinfob->parent = 0;

		printf("%s%d nodes examined. %ld elements in the hash%s\n",
			html ? "<HR>" : "",
			rec,
			hashelements(),
			html ? "<BR>" : "");
		if (keyinfoa->colour == 0) {
			if (pathnum == 0) {
				printf("Can't find a link from 0x%08llX to "
				"0x%08llX%s\n",
				have,
				want,
				html ? "<BR>" : "");
			} else {
				printf("Can't find any further paths%s\n",
					html ? "<BR>" : "");
			}
			pathnum = count;
		} else {
			printf("%d steps from 0x%08llX to 0x%08llX%s\n",
				keyinfoa->colour, have & 0xFFFFFFFF,
				want & 0xFFFFFFFF,
				html ? "<BR>" : "");
			curkey = keyinfoa;
			while (curkey != NULL && curkey->keyid != 0) {
				uid = keyid2uid(curkey->keyid);
				if (html && uid == NULL) {
					printf("<a href=\"lookup?op=get&search="
						"0x%08llX\">0x%08llX</a> (["
						"User id not found])%s<BR>\n",
						curkey->keyid & 0xFFFFFFFF,
						curkey->keyid & 0xFFFFFFFF,
						(curkey->keyid == fullwant) ?
							"" : " signs");
				} else if (html && uid != NULL) {
					printf("<a href=\"lookup?op=get&search="
						"0x%08llX\">0x%08llX</a>"
						" (<a href=\"lookup?op=vindex&"
						"search=0x%08llX\">%s</a>)%s"
						"<BR>\n",
						curkey->keyid & 0xFFFFFFFF,
						curkey->keyid & 0xFFFFFFFF,
						curkey->keyid & 0xFFFFFFFF,
						txt2html(uid),
						(curkey->keyid == fullwant) ?
						"" : " signs");
				} else {
					printf("0x%08llX (%s)%s\n",
						curkey->keyid & 0xFFFFFFFF,
						(uid == NULL) ?
							"[User id not found]" :
							uid,
						(curkey->keyid == fullwant) ?
						"" : " signs");
				}
				if (uid != NULL) {
					free(uid);
					uid = NULL;
				}
				if (curkey != keyinfoa && curkey != keyinfob) {
					curkey->disabled = true;
				}
				curkey = findinhash(curkey->parent);
			}
			if (html) {
				puts("<P>List of key ids in path:</P>");
			} else {
				puts("List of key ids in path:");
			}
			curkey = keyinfoa;
			while (curkey != NULL && curkey->keyid != 0) {
				printf("0x%08llX ", curkey->keyid & 0xFFFFFFFF);
				curkey = findinhash(curkey->parent);
			}
			putchar('\n');
		}
		pathnum++;
	}
}



struct stats_key *furthestkey(struct stats_key *have)
{
	unsigned long count = 0;
	unsigned long curdegree = 0;
	struct ll *curll, *nextll, *tmp;
	struct ll *sigs = NULL;
	struct stats_key *max;

	if (have == NULL) {
		return NULL;
	}

	++curdegree;

	nextll = NULL;
	max = have;
	curll = lladd(NULL, have);

	while (curll != NULL) {
		sigs = cached_getkeysigs(((struct stats_key *)
				curll->object)->keyid);
		while (sigs != NULL) {
			if (((struct stats_key *) sigs->object)->colour == 0) {
				/*
				 * We've never seen it. Count it, mark it and
				 * explore its subtree.
				 */
				count++;
				max = (struct stats_key *)sigs->object;
				((struct stats_key *)sigs->object)->colour = 
					curdegree;
				((struct stats_key *)sigs->object)->parent = 
					((struct stats_key *)
					 curll->object)->keyid;
				
				nextll=lladd(nextll, sigs->object);
			}
			sigs=sigs->next;
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

	return max;
}
