/*
 * stats.c - various routines to do stats on the key graph
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2000-2002 Project Purple
 */

#include <stdlib.h>

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
	struct ll *sigs = NULL;
	struct ll *nextkeys = NULL;
	long curdegree = 0;
	long count = 0;
	
	curdegree = 1;
	keys = lladd(NULL, want);

	while (keys != NULL && have->colour == 0) {
		sigs = hash_getkeysigs(((struct stats_key *)
					keys->object)->keyid);
		while (sigs != NULL && have->colour == 0) {
			/*
			 * Check if we've seen this key before and if not mark
			 * it and add its sigs to the list we want to look at.
			 */
			if (((struct stats_key *)sigs->object)->colour == 0) {
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
			nextkeys = NULL;
			curdegree++;
		}
	}

	return count;
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
		sigs = hash_getkeysigs(((struct stats_key *)
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
