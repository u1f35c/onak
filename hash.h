/*
 * hash.h - hashing routines mainly used for caching key details.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2000-2002 Project Purple
 *
 * $Id: hash.h,v 1.5 2003/10/11 21:52:18 noodles Exp $
 */

#ifndef __HASH_H__
#define __HASH_H__

#include "keystructs.h"
#include "ll.h"

#define HASHSIZE 1024
#define HASHMASK 0x3FF

/**
 *	inithash - Initialize the hash ready for use.
 *
 *	This function prepares the hash ready for use. It should be called
 *	before any of the functions below are used.
 */
void inithash(void);

/**
 *	destroyhash - Clean up the hash after use.
 *
 *	This function destroys the hash after use, freeing any memory that was
 *	used during its lifetime.
 */
void destroyhash(void);

/**
 *	addtohash - Adds a key to the hash.
 *	@key: The key to add.
 *
 *	Takes a key and stores it in the hash.
 */
void addtohash(struct stats_key *key);

/**
 *	createandaddtohash - Creates a key and adds it to the hash.
 *	@keyid: The key to create and add.
 *
 *	Takes a key, checks if it exists in the hash and if not creates it
 *	and adds it to the hash. Returns the key from the hash whether it
 *	already existed or we just created it.
 */
struct stats_key *createandaddtohash(uint64_t keyid);

/**
 *	findinhash - Finds a key in the hash.
 *	@keyid: The key we want.
 *
 *	Finds a key in the hash and returns it.
 */
struct stats_key *findinhash(uint64_t keyid);

/**
 *	hashelements - Returns the size of the hash
 *
 *	Returns the number of elements that have been loaded into the hash.
 */
unsigned long hashelements(void);

/**
 *	gethashtableentry - Returns an entry from the hash table.
 *	@entry: The entry to return. 0 <= entry < HASHSIZE must hold.
 *
 *	Gets a particular entry from the hash. Useful for doing something over
 *	all entries in the hash.
 */
struct ll *gethashtableentry(unsigned int entry);

#endif /* __HASH_H__ */
