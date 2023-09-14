/*
 * stats.c - various routines to do stats on the key graph
 *
 * Copyright 2000-2004,2007-2009 Jonathan McDowell <noodles@earth.li>
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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "cleanup.h"
#include "hash.h"
#include "keydb.h"
#include "keyindex.h"
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
	unsigned int loop;
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
unsigned long findpath(struct onak_dbctx *dbctx,
		struct stats_key *have, struct stats_key *want)
{
	struct ll *keys = NULL;
	struct ll *oldkeys = NULL;
	struct ll *sigs = NULL;
	struct ll *nextkeys = NULL;
	long curdegree = 0;
	unsigned long count = 0;
	
	curdegree = 1;
	keys = lladd(NULL, want);
	oldkeys = keys;

	while ((!cleanup()) && keys != NULL && have->colour == 0) {
		sigs = dbctx->cached_getkeysigs(dbctx, ((struct stats_key *)
					keys->object)->keyid);
		while ((!cleanup()) && sigs != NULL && have->colour == 0) {
			/*
			 * Check if we've seen this key before and if not mark
			 * it and add its sigs to the list we want to look at.
			 */
			if (!((struct stats_key *)sigs->object)->disabled &&
			    !((struct stats_key *)sigs->object)->revoked &&
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
void dofindpath(struct onak_dbctx *dbctx,
		uint64_t have, uint64_t want, bool html, int count)
{
	struct stats_key *keyinfoa, *keyinfob, *curkey;
	int rec;
	int pathnum;
	char *uid;

	/*
	 * Make sure the keys we have and want are in the cache.
	 */
	(void) dbctx->cached_getkeysigs(dbctx, have);
	(void) dbctx->cached_getkeysigs(dbctx, want);

	if ((keyinfoa = findinhash(have)) == NULL) {
		printf("Couldn't find key 0x%016" PRIX64 ".\n", have);
		return;
	}
	if ((keyinfob = findinhash(want)) == NULL) {
		printf("Couldn't find key 0x%016" PRIX64 ".\n", want);
		return;
	}

	pathnum = 0;
	
	while ((!cleanup()) && (pathnum < count)) {
		/*
		 * Fill the tree info up.
		 */
		initcolour(true);
		rec = findpath(dbctx, keyinfoa, keyinfob);
		keyinfob->parent = 0;

		printf("%s%d nodes examined. %ld elements in the hash%s\n",
			html ? "<HR>" : "",
			rec,
			hashelements(),
			html ? "<BR>" : "");
		if (keyinfoa->colour == 0) {
			if (pathnum == 0) {
				printf("Can't find a link from 0x%016" PRIX64
				" to 0x%016" PRIX64 "%s\n",
				have,
				want,
				html ? "<BR>" : "");
			} else {
				printf("Can't find any further paths%s\n",
					html ? "<BR>" : "");
			}
			pathnum = count;
		} else {
			printf("%d steps from 0x%016" PRIX64 " to 0x%016"
				PRIX64 "%s\n",
				keyinfoa->colour, have,
				want,
				html ? "<BR>" : "");
			curkey = keyinfoa;
			while (curkey != NULL && curkey->keyid != 0) {
				uid = dbctx->keyid2uid(dbctx,
						curkey->keyid);
				if (html && uid == NULL) {
					printf("<a href=\"lookup?op=get&search="
						"0x%016" PRIX64 "\">0x%016"
						PRIX64 "</a> (["
						"User id not found])%s<BR>\n",
						curkey->keyid,
						curkey->keyid,
						(curkey->keyid == want) ?
							"" : " signs");
				} else if (html && uid != NULL) {
					printf("<a href=\"lookup?op=get&search="
						"0x%016" PRIX64 "\">0x%016"
						PRIX64 "</a>"
						" (<a href=\"lookup?op=vindex&"
						"search=0x%016" PRIX64
						"\">%s</a>)%s"
						"<BR>\n",
						curkey->keyid,
						curkey->keyid,
						curkey->keyid,
						txt2html(uid),
						(curkey->keyid == want) ?
						"" : " signs");
				} else {
					printf("0x%016" PRIX64 " (%s)%s\n",
						curkey->keyid,
						(uid == NULL) ?
							"[User id not found]" :
							uid,
						(curkey->keyid == want) ?
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
				printf("0x%016" PRIX64 " ",
						curkey->keyid);
				curkey = findinhash(curkey->parent);
			}
			putchar('\n');
		}
		pathnum++;
	}
}



struct stats_key *furthestkey(struct onak_dbctx *dbctx, struct stats_key *have)
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
		sigs = dbctx->cached_getkeysigs(dbctx, ((struct stats_key *)
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
