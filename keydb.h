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
 *	starttrans - Start a transaction.
 *
 *	Start a transaction. Intended to be used if we're about to perform many
 *	operations on the database to help speed it all up, or if we want
 *	something to only succeed if all relevant operations are successful.
 */
bool starttrans(void);

/**
 *	endtrans - End a transaction.
 *
 *	Ends a transaction.
 */
void endtrans(void);

/**
 *	fetch_key - Given a keyid fetch the key from storage.
 *	@keyid: The keyid to fetch.
 *	@publickey: A pointer to a structure to return the key in.
 *	@intrans: If we're already in a transaction.
 *
 *	This function returns a public key from whatever storage mechanism we
 *	are using.
 *
 *      TODO: What about keyid collisions? Should we use fingerprint instead?
 */
int fetch_key(uint64_t keyid, struct openpgp_publickey **publickey, bool intrans);

/**
 *	store_key - Takes a key and stores it.
 *	@publickey: A pointer to the public key to store.
 *	@intrans: If we're already in a transaction.
 *	@update: If true the key exists and should be updated.
 *
 *	This function stores a public key in whatever storage mechanism we are
 *	using. intrans indicates if we're already in a transaction so don't
 *	need to start one. update indicates if the key already exists and is
 *	just being updated.
 *
 *	TODO: Do we store multiple keys of the same id? Or only one and replace
 *	it?
 */
int store_key(struct openpgp_publickey *publickey, bool intrans, bool update);

/**
 *	delete_key - Given a keyid delete the key from storage.
 *	@keyid: The keyid to delete.
 *	@intrans: If we're already in a transaction.
 *
 *	This function deletes a public key from whatever storage mechanism we
 *	are using. Returns 0 if the key existed.
 */
int delete_key(uint64_t keyid, bool intrans);

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

/**
 *	cached_getkeysigs - Gets the signatures on a key.
 *	@keyid: The key we want the signatures for.
 *	
 *	This function gets the signatures on a key. It's the same as the
 *	getkeysigs function above except we use the hash module to cache the
 */
struct ll *cached_getkeysigs(uint64_t keyid);

/**
 *	getfullkeyid - Maps a 32bit key id to a 64bit one.
 *	@keyid: The 32bit keyid.
 *
 *	This function maps a 32bit key id to the full 64bit one. It returns the
 *	full keyid. If the key isn't found a keyid of 0 is returned.
 */
uint64_t getfullkeyid(uint64_t keyid);

#endif /* __KEYDB_H__ */
