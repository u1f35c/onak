/*
 * hash.h - hashing routines mainly used for caching key details.
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
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __HASH_H__
#define __HASH_H__

#include "keystructs.h"
#include "ll.h"
#include "stats.h"

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
