/*
 * hash.c - hashing routines mainly used for caching key details.
 *
 * Copyright 2000-2002 Jonathan McDowell <noodles@earth.li>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "keystructs.h"
#include "ll.h"
#include "mem.h"
#include "stats.h"

/**
 *	hashtable - the hash table array.
 */
static struct ll *hashtable[HASHSIZE];

/**
 *	elements - the number of elements in the hash table.
 */
static unsigned long elements;

/**
 *	free_statskey - free an stats key structure.
 *	@key: The key to free.
 *
 *	Takes a stats key and frees the memory used by it and the linked list
 *	of sigs under it. Doesn't recurse into the list as it's assumed all the
 *	objects referenced also exist in the hash.
 */
static void free_statskey(struct stats_key *key)
{
	if (key != NULL) {
		if (key->sigs != NULL) {
			llfree(key->sigs, NULL);
			key->sigs = NULL;
		}
		if (key->signs != NULL) {
			llfree(key->signs, NULL);
			key->signs = NULL;
		}
		free(key);
	}
}

/**
 *	inithash - Initialize the hash ready for use.
 */
void inithash(void)
{
	unsigned int i;

	for (i = 0; i < HASHSIZE; i++) {
		hashtable[i] = NULL;
	}
	elements = 0;
}

/**
 *	destroyhash - Clean up the hash after use.
 *
 *	This function destroys the hash after use, freeing any memory that was
 *	used during its lifetime.
 */
void destroyhash(void)
{
	int i;
	struct ll *curll = NULL;

	for (i = 0; i < HASHSIZE; i++) {
		curll = hashtable[i];
		/*
		 * TODO: The problem is the object has pointers that
		 * need freed too.
		 */
		llfree(curll, (void (*)(void *)) free_statskey);
		hashtable[i] = NULL;
	}
	elements = 0;
}

/**
 *	addtohash - Adds a key to the hash.
 *	@key: The key to add.
 *
 *	Takes a key and stores it in the hash.
 */
void addtohash(struct stats_key *key)
{
	++elements;
	hashtable[key->keyid & HASHMASK]=
		lladd(hashtable[key->keyid & HASHMASK], key);
}

/**
 *	createandaddtohash - Creates a key and adds it to the hash.
 *	@keyid: The key to create and add.
 *
 *	Takes a key, checks if it exists in the hash and if not creates it
 *	and adds it to the hash. Returns the key from the hash whether it
 *	already existed or we just created it.
 */
struct stats_key *createandaddtohash(uint64_t keyid)
{
	struct stats_key *tmpkey;

	/*
	 * Check if the key already exists and if not create and add it.
	 */
	tmpkey = findinhash(keyid);
	if (tmpkey == NULL) {
		tmpkey = malloc(sizeof(*tmpkey));
		memset(tmpkey, 0, sizeof(*tmpkey));
		tmpkey->keyid = keyid;
		addtohash(tmpkey);
	}
	return tmpkey;
}

static int stats_key_cmp(struct stats_key *key, uint64_t *keyid)
{
	return !(key != NULL && key->keyid == *keyid);
}

struct stats_key *findinhash(uint64_t keyid)
{
	int (*p)(const void *, const void *);
	struct ll *found;

	p = (int (*)(const void *, const void *))stats_key_cmp;
	if ((found = llfind(hashtable[keyid & HASHMASK], &keyid, p))==NULL) {
		return NULL;
	}
	return found->object;
}

unsigned long hashelements(void)
{
	return elements;
}

struct ll *gethashtableentry(unsigned int entry)
{
	return hashtable[entry];
}
