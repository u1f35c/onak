/*
 * hash.c - hashing routines mainly used for caching key details.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2000-2002 Project Purple
 */

#include <stdio.h>
#include <stdlib.h>

#include "hash.h"
#include "keydb.h"
#include "keyid.h"
#include "ll.h"
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
		llfree(curll, free);
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

int stats_key_cmp(struct stats_key *key, uint64_t *keyid)
{
	return !(key != NULL && key->keyid == *keyid);
}

struct stats_key *findinhash(uint64_t keyid)
{
	int (*p)();
	struct ll *found;

	p = stats_key_cmp;
	if ((found = llfind(hashtable[keyid & HASHMASK], &keyid, p))==NULL) {
		return NULL;
	}
	return found->object;
}

unsigned long hashelements(void)
{
	return elements;
}

struct ll *gethashtableentry(int entry)
{
	return hashtable[entry];
}

/**
 *	hash_getkeysigs - Gets the signatures on a key.
 *	@keyid: The key we want the signatures for.
 *	
 *	This function gets the signatures on a key. It's the same as the
 *	getkeysigs function from the keydb module except we also cache the data
 *	so that if we need it again we already have it available.
 */
struct ll *hash_getkeysigs(uint64_t keyid)
{
	struct stats_key *key = NULL;

	key = findinhash(keyid);
	if (key == NULL) {
		key = malloc(sizeof(*key));
		if (key != NULL) {
			key->keyid = keyid;
			key->colour = 0;
			key->parent = 0;
			key->sigs = NULL;
			key->gotsigs = false;
			addtohash(key);
		} else {
			perror("hash_getkeysigs()");
			return NULL;
		}
	}
	if (key->gotsigs == false) {
		key->sigs = getkeysigs(key->keyid);
		key->gotsigs = true;
	}

	return key->sigs;
}
