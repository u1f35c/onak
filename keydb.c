/*
 * keydb.c - Routines for DB access that just use store/fetch.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

/**
 *	The routines in this file are meant to be used as an initial step when
 *	adding a new db access module. They provide various functions required
 *	of the db access module using only the store and fetch functions. As
 *	they need to parse the actual OpenPGP data to work they are a lot
 *	slower than custom functions however.
 */

#include <stdio.h>

#include "decodekey.h"
#include "hash.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "mem.h"
#include "parsekey.h"

#ifdef NEED_KEYID2UID
/**
 *	keyid2uid - Takes a keyid and returns the primary UID for it.
 *	@keyid: The keyid to lookup.
 */
char *keyid2uid(uint64_t keyid)
{
	struct openpgp_publickey *publickey = NULL;
	struct openpgp_signedpacket_list *curuid = NULL;
	char buf[1024];

	buf[0]=0;
	if (fetch_key(keyid, &publickey, false) && publickey != NULL) {
		curuid = publickey->uids;
		while (curuid != NULL && buf[0] == 0) {
			if (curuid->packet->tag == 13) {
				snprintf(buf, 1023, "%.*s",
						(int) curuid->packet->length,
						curuid->packet->data);
			}
			curuid = curuid -> next;
		}
		free_publickey(publickey);
	}

	if (buf[0] == 0) {
		return NULL;
	} else {
		return strdup(buf);
	}
}
#endif

#ifdef NEED_GETKEYSIGS
/**
 *	getkeysigs - Gets a linked list of the signatures on a key.
 *	@keyid: The keyid to get the sigs for.
 *
 *	This function gets the list of signatures on a key. Used for key 
 *	indexing and doing stats bits.
 */
struct ll *getkeysigs(uint64_t keyid)
{
	struct ll *sigs = NULL;
	struct openpgp_signedpacket_list *uids = NULL;
	struct openpgp_publickey *publickey = NULL;

	fetch_key(keyid, &publickey, false);
	
	if (publickey != NULL) {
		for (uids = publickey->uids; uids != NULL; uids = uids->next) {
			sigs = keysigs(sigs, uids->sigs);
		}
		free_publickey(publickey);
	}

	return sigs;
}
#endif

/**
 *	cached_getkeysigs - Gets the signatures on a key.
 *	@keyid: The key we want the signatures for.
 *	
 *	This function gets the signatures on a key. It's the same as the
 *	getkeysigs function above except we use the hash module to cache the
 *	data so if we need it again it's already loaded.
 */
struct ll *cached_getkeysigs(uint64_t keyid)
{
	struct stats_key *key = NULL;

	if (keyid == 0)  {
		return NULL;
	}

	key = findinhash(keyid);
	if (key == NULL) {
		key = malloc(sizeof(*key));
		if (key != NULL) {
			key->keyid = keyid;
			key->colour = 0;
			key->parent = 0;
			key->sigs = NULL;
			key->gotsigs = false;
			key->disabled = false;
			addtohash(key);
		} else {
			perror("cached_getkeysigs()");
			return NULL;
		}
	}
	if (key->gotsigs == false) {
		key->sigs = getkeysigs(key->keyid);
		key->gotsigs = true;
	}

	return key->sigs;
}

#ifdef NEED_GETFULLKEYID
/**
 *	getfullkeyid - Maps a 32bit key id to a 64bit one.
 *	@keyid: The 32bit keyid.
 *
 *	This function maps a 32bit key id to the full 64bit one. It returns the
 *	full keyid. If the key isn't found a keyid of 0 is returned.
 */
uint64_t getfullkeyid(uint64_t keyid)
{
	struct openpgp_publickey *publickey = NULL;

	if (keyid < 0x100000000LL) {
		fetch_key(keyid, &publickey, false);
		if (publickey != NULL) {
			keyid = get_keyid(publickey);
			free_publickey(publickey);
			publickey = NULL;
		} else {
			keyid = 0;
		}
	}
	
	return keyid;
}
#endif
