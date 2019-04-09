/*
 * keydb.c - Routines for DB access that just use store/fetch.
 *
 * Copyright 2002-2004 Jonathan McDowell <noodles@earth.li>
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

/**
 *	The routines in this file are meant to be used as an initial step when
 *	adding a new db access module. They provide various functions required
 *	of the db access module using only the store and fetch functions. As
 *	they need to parse the actual OpenPGP data to work they are a lot
 *	slower than custom functions however.
 */

#include <stdbool.h>
#include <stdio.h>

#include "decodekey.h"
#include "hash.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "ll.h"
#include "mem.h"
#include "merge.h"
#include "openpgp.h"
#include "sendsync.h"
#include "stats.h"

#ifdef NEED_KEYID2UID
/**
 *	keyid2uid - Takes a keyid and returns the primary UID for it.
 *	@keyid: The keyid to lookup.
 */
char *generic_keyid2uid(struct onak_dbctx *dbctx, uint64_t keyid)
{
	struct openpgp_publickey *publickey = NULL;
	struct openpgp_signedpacket_list *curuid = NULL;
	char buf[1024];

	buf[0]=0;
	if (dbctx->fetch_key_id(dbctx, keyid, &publickey, false) &&
			publickey != NULL) {
		curuid = publickey->uids;
		while (curuid != NULL && buf[0] == 0) {
			if (curuid->packet->tag == OPENPGP_PACKET_UID) {
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
 *	@revoked: Is the key revoked?
 *
 *	This function gets the list of signatures on a key. Used for key 
 *	indexing and doing stats bits. If revoked is non-NULL then if the key
 *	is revoked it's set to true.
 */
struct ll *generic_getkeysigs(struct onak_dbctx *dbctx,
		uint64_t keyid, bool *revoked)
{
	struct ll *sigs = NULL;
	struct openpgp_signedpacket_list *uids = NULL;
	struct openpgp_publickey *publickey = NULL;

	dbctx->fetch_key_id(dbctx, keyid, &publickey, false);
	
	if (publickey != NULL) {
		for (uids = publickey->uids; uids != NULL; uids = uids->next) {
			sigs = keysigs(sigs, uids->sigs);
		}
		if (revoked != NULL) {
			*revoked = publickey->revoked;
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
struct ll *generic_cached_getkeysigs(struct onak_dbctx *dbctx, uint64_t keyid)
{
	struct stats_key *key = NULL;
	struct stats_key *signedkey = NULL;
	struct ll        *cursig = NULL;
	struct ll	 *sigs = NULL;
	bool		  revoked = false;

	if (keyid == 0)  {
		return NULL;
	}

	key = findinhash(keyid);

	if (key == NULL || key->gotsigs == false) {
		sigs = dbctx->getkeysigs(dbctx, keyid, &revoked);
		if (sigs == NULL) {
			return NULL;
		}
		if (key == NULL) {
			key = createandaddtohash(keyid);
		}
		key->sigs = sigs;
		key->revoked = revoked;
		for (cursig = key->sigs; cursig != NULL;
				cursig = cursig->next) {
			signedkey = (struct stats_key *) cursig->object;
			signedkey->signs = lladd(signedkey->signs, key);
		}
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
uint64_t generic_getfullkeyid(struct onak_dbctx *dbctx, uint64_t keyid)
{
	struct openpgp_publickey *publickey = NULL;

	if (keyid < 0x100000000LL) {
		dbctx->fetch_key_id(dbctx, keyid, &publickey, false);
		if (publickey != NULL) {
			get_keyid(publickey, &keyid);
			free_publickey(publickey);
			publickey = NULL;
		} else {
			keyid = 0;
		}
	}
	
	return keyid;
}
#endif

#ifdef NEED_UPDATEKEYS
/**
 *	update_keys - Takes a list of public keys and updates them in the DB.
 *	@keys: The keys to update in the DB.
 *	@sendsync: Should we send a sync mail to our peers.
 *
 *	Takes a list of keys and adds them to the database, merging them with
 *	the key in the database if it's already present there. The key list is
 *	update to contain the minimum set of updates required to get from what
 *	we had before to what we have now (ie the set of data that was added to
 *	the DB). Returns the number of entirely new keys added.
 */
int generic_update_keys(struct onak_dbctx *dbctx,
		struct openpgp_publickey **keys, bool sendsync)
{
	struct openpgp_publickey *curkey = NULL;
	struct openpgp_publickey *oldkey = NULL;
	struct openpgp_publickey *prev = NULL;
	int newkeys = 0;
	bool intrans;
	uint64_t keyid;

	for (curkey = *keys; curkey != NULL; curkey = curkey->next) {
		intrans = dbctx->starttrans(dbctx);
		get_keyid(curkey, &keyid);
		logthing(LOGTHING_INFO,
			"Fetching key 0x%" PRIX64 ", result: %d",
			keyid,
			dbctx->fetch_key_id(dbctx, keyid, &oldkey,
					intrans));

		/*
		 * If we already have the key stored in the DB then merge it
		 * with the new one that's been supplied. Otherwise the key
		 * we've just got is the one that goes in the DB and also the
		 * one that we send out.
		 */
		if (oldkey != NULL) {
			merge_keys(oldkey, curkey);
			if (curkey->sigs == NULL &&
					curkey->uids == NULL &&
					curkey->subkeys == NULL) {
				if (prev == NULL) {
					*keys = curkey->next;
				} else {
					prev->next = curkey->next;
					curkey->next = NULL;
					free_publickey(curkey);
					curkey = prev;
				}
			} else {
				prev = curkey;
				logthing(LOGTHING_INFO,
					"Merged key; storing updated key.");
				dbctx->store_key(dbctx, oldkey, intrans,
					true);
			}
			free_publickey(oldkey);
			oldkey = NULL;
		} else {
			logthing(LOGTHING_INFO,
				"Storing completely new key.");
			dbctx->store_key(dbctx, curkey, intrans, false);
			newkeys++;
		}
		dbctx->endtrans(dbctx);
	}

	if (sendsync && keys != NULL) {
		sendkeysync(*keys);
	}

	return newkeys;
}
#endif /* NEED_UPDATEKEYS */

#ifdef NEED_GET_FP
static int generic_fetch_key_fp(struct onak_dbctx *dbctx,
		struct openpgp_fingerprint *fingerprint,
		struct openpgp_publickey **publickey, bool intrans)
{
	uint64_t keyid;
	int i;

	if (fingerprint->length > MAX_FINGERPRINT_LEN) {
		return 0;
	}

	/*
	 * We assume if the backend is using this function it's not storing
	 * anything bigger than the 64 bit key ID and just truncate the
	 * fingerprint to get that value. This doesn't work for v3 keys,
	 * but there's no way to map from v3 fingerprint to v3 key ID so
	 * if the backend can't do it we're going to fail anyway.
	 */
	keyid = 0;
	for (i = (fingerprint->length - 8); i < fingerprint->length; i++) {
		keyid = (keyid << 8) + fingerprint->fp[i];
	}

	return dbctx->fetch_key_id(dbctx, keyid, publickey, intrans);
}
#endif
