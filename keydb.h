/*
 * keydb.h - Routines to store and fetch keys.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#ifndef __KEYDB_H__
#define __KEYDB_H__

// #include <stdint.h>
#include <inttypes.h>

#include "keystructs.h"
#include "ll.h"

/**
 *	initdb - Initialize the key database.
 *
 *	This function should be called before any of the other functions in
 *	this file are called in order to allow the DB to be initialized ready
 *	for access.
 */
void initdb(void);

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	This function should be called upon program exit to allow the DB to
 *	cleanup after itself.
 */
void cleanupdb(void);

/**
 *	fetch_key - Given a keyid fetch the key from storage.
 *	@keyid: The keyid to fetch.
 *	@publickey: A pointer to a structure to return the key in.
 *
 *	This function returns a public key from whatever storage mechanism we
 *	are using.
 *
 *      TODO: What about keyid collisions? Should we use fingerprint instead?
 */
int fetch_key(uint64_t keyid, struct openpgp_publickey **publickey);

/**
 *	store_key - Takes a key and stores it.
 *	@publickey: A pointer to the public key to store.
 *
 *	This function stores a public key in whatever storage mechanism we are
 *	using.
 *
 *	TODO: Do we store multiple keys of the same id? Or only one and replace
 *	it?
 */
int store_key(struct openpgp_publickey *publickey);

/**
 *	delete_key - Given a keyid delete the key from storage.
 *	@keyid: The keyid to delete.
 *
 *	This function deletes a public key from whatever storage mechanism we
 *	are using. Returns 0 if the key existed.
 */
int delete_key(uint64_t keyid);

/**
 *	fetch_key_text - Trys to find the keys that contain the supplied text.
 *	@search: The text to search for.
 *	@publickey: A pointer to a structure to return the key in.
 *
 *	This function searches for the supplied text and returns the keys that
 *	contain it.
 */
int fetch_key_text(const char *search, struct openpgp_publickey **publickey);

/**
 *	keyid2uid - Takes a keyid and returns the primary UID for it.
 *	@keyid: The keyid to lookup.
 *
 *	This function returns a UID for the given key. Returns NULL if the key
 *	isn't found.
 */
char *keyid2uid(uint64_t keyid);

/**
 *	getkeysigs - Gets a linked list of the signatures on a key.
 *	@keyid: The keyid to get the sigs for.
 *
 *	This function gets the list of signatures on a key. Used for key 
 *	indexing and doing stats bits.
 */
struct ll *getkeysigs(uint64_t keyid);

#endif /* __KEYDB_H__ */
