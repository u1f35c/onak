/*
 * keydb_dynamic.c - backend that can load the other backends
 *
 * Brett Parker <iDunno@sommitrealweird.co.uk>
 *
 * Copyright 2005 Project Purple
 */

#include <stdio.h>

#include "decodekey.h"
#include "hash.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "mem.h"
#include "merge.h"
#include "parsekey.h"
#include "sendsync.h"
#include "keydb_dynamic.h"

struct dynamic_backend *get_backend(void)
{
	return &__dynamicdb_backend__;
}

bool backend_loaded(void)
{
	return __dynamicdb_backend__.loaded;
}

bool load_backend(void)
{
	char *soname = NULL;
	void *handle;
	struct dynamic_backend *backend = get_backend();

	if (backend->loaded) {
		close_backend();
	}

	if (!config.db_backend) {
		logthing(LOGTHING_CRITICAL, "No database backend defined.");
		exit(EXIT_FAILURE);
	}

	if (config.backends_dir == NULL) {
		soname = malloc(strlen(config.db_backend)
			+ strlen("./libkeydb_")
			+ strlen(".so")
			+ 1);

		sprintf(soname, "./libkeydb_%s.so", config.db_backend);
	} else {
		soname = malloc(strlen(config.db_backend)
			+ strlen("/libkeydb_")
			+ strlen(".so")
			+ strlen(config.backends_dir)
			+ 1);

		sprintf(soname, "%s/libkeydb_%s.so", config.backends_dir,
			config.db_backend);
	}
		
	logthing(LOGTHING_INFO, "Loading dynamic backend: %s", soname);

	handle = dlopen(soname, RTLD_LAZY);
	if (handle == NULL) {
		logthing(LOGTHING_CRITICAL,
				"Failed to open handle to library '%s': %s",
				soname, dlerror());
		free(soname);
		soname = NULL;
		exit(EXIT_FAILURE);
	}
	free(soname);
	soname = NULL;

	backend->initdb = (initdbfunc_t) dlsym(handle, "initdb");
	backend->cleanupdb = (cleanupdbfunc_t) dlsym(handle, "cleanupdb");
	backend->starttrans = (starttransfunc_t) dlsym(handle, "starttrans");
	backend->endtrans = (endtransfunc_t) dlsym(handle, "endtrans");
	backend->fetch_key = (fetch_keyfunc_t) dlsym(handle, "fetch_key");
	backend->store_key = (store_keyfunc_t) dlsym(handle, "store_key");
	backend->delete_key = (delete_keyfunc_t) dlsym(handle, "delete_key");
	backend->fetch_key_text = (fetch_key_textfunc_t)
				  dlsym (handle, "fetch_key_text");
	backend->update_keys = (update_keysfunc_t)
			       dlsym(handle, "update_keys");
	backend->keyid2uid = (keyid2uidfunc_t) dlsym(handle, "keyid2uid");
	backend->cached_getkeysigs = (cached_getkeysigsfunc_t)
				     dlsym(handle, "cached_getkeysigs");
	backend->getfullkeyid = (getfullkeyidfunc_t)
				dlsym(handle, "getfullkeyid");
	backend->iterate_keys = (iterate_keysfunc_t)
				dlsym(handle, "iterate_keys");

	backend->handle = handle;
	backend->loaded = true;

	return true;
}

bool close_backend(void)
{
	struct dynamic_backend *backend;
	backend = get_backend();
	
	backend->initdb = NULL;
	backend->cleanupdb = NULL;
	backend->starttrans = NULL;
	backend->endtrans = NULL;
	backend->fetch_key = NULL;
	backend->store_key = NULL;
	backend->delete_key = NULL;
	backend->fetch_key_text = NULL;
	backend->update_keys = NULL;
	backend->keyid2uid = NULL;
	backend->cached_getkeysigs = NULL;
	backend->getfullkeyid = NULL;
	backend->iterate_keys = NULL;
	backend->loaded = false;
	dlclose(backend->handle);
	backend->handle = NULL;

	return true;
}

/**
 *	keyid2uid - Takes a keyid and returns the primary UID for it.
 *	@keyid: The keyid to lookup.
 */
char *keyid2uid(uint64_t keyid)
{
	struct openpgp_publickey *publickey = NULL;
	struct openpgp_signedpacket_list *curuid = NULL;
	char buf[1024];

	struct dynamic_backend *backend;
	if (!backend_loaded()) {
		load_backend();
	}
	
	if (backend_loaded()) {
		backend = get_backend();
		if (backend->keyid2uid != NULL) {
			return backend->keyid2uid(keyid);
		}
	}
	
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

/**
 *	getkeysigs - Gets a linked list of the signatures on a key.
 *	@keyid: The keyid to get the sigs for.
 *	@revoked: Is the key revoked?
 *
 *	This function gets the list of signatures on a key. Used for key 
 *	indexing and doing stats bits. If revoked is non-NULL then if the key
 *	is revoked it's set to true.
 */
struct ll *getkeysigs(uint64_t keyid, bool *revoked)
{
	struct ll *sigs = NULL;
	struct openpgp_signedpacket_list *uids = NULL;
	struct openpgp_publickey *publickey = NULL;
	
	struct dynamic_backend *backend;
	if ( !backend_loaded() ) {
		load_backend();
	}
	
	if (backend_loaded()) {
		backend = get_backend();
		if (backend->getkeysigs != NULL) {
			return backend->getkeysigs(keyid,revoked);
		}
	}

	fetch_key(keyid, &publickey, false);
	
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
	struct stats_key *signedkey = NULL;
	struct ll        *cursig = NULL;
	bool		  revoked = false;
	
	struct dynamic_backend *backend;

	if (keyid == 0)  {
		return NULL;
	}
	
	if (!backend_loaded()) {
		load_backend();
	}
	
	if (backend_loaded()) {
		backend = get_backend();
		if (backend->cached_getkeysigs != NULL) {
			return backend->cached_getkeysigs(keyid);
		}
	}

	key = createandaddtohash(keyid);

	if (key->gotsigs == false) {
		key->sigs = getkeysigs(key->keyid, &revoked);
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
	struct dynamic_backend *backend;
	
	if (!backend_loaded()) {
		load_backend();
	}
	
	if (backend_loaded()) {
		backend = get_backend();
		if (backend->getfullkeyid != NULL) {
			return backend->getfullkeyid(keyid);
		}
	}

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
int update_keys(struct openpgp_publickey **keys, bool sendsync)
{
	struct openpgp_publickey *curkey = NULL;
	struct openpgp_publickey *oldkey = NULL;
	struct openpgp_publickey *prev = NULL;
	struct dynamic_backend *backend;
	int newkeys = 0;
	bool intrans;
	
	if (!backend_loaded()) {
		load_backend();
	}
	
	if (backend_loaded()) {
		backend = get_backend();
		if (backend->update_keys != NULL) {
			return backend->update_keys(keys, sendsync);
		}
	}

	for (curkey = *keys; curkey != NULL; curkey = curkey->next) {
		intrans = starttrans();
		logthing(LOGTHING_INFO,
			"Fetching key 0x%llX, result: %d",
			get_keyid(curkey),
			fetch_key(get_keyid(curkey), &oldkey, intrans));

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
				store_key(oldkey, intrans, true);
			}
			free_publickey(oldkey);
			oldkey = NULL;
		
		} else {
			logthing(LOGTHING_INFO,
				"Storing completely new key.");
			store_key(curkey, intrans, false);
			newkeys++;
		}
		endtrans();
		intrans = false;
	}

	if (sendsync && keys != NULL) {
		sendkeysync(*keys);
	}

	return newkeys;
}

void initdb(bool readonly)
{
	struct dynamic_backend *backend;
	backend = get_backend();
	
	if (!backend_loaded()) {
		load_backend();
	}

	if (backend->loaded) {
		if (backend->initdb != NULL) {
			backend->initdb(readonly);
		}
	}
}

void cleanupdb(void)
{
	struct dynamic_backend *backend;
	backend = get_backend();

	if (backend->loaded) {
		if (backend->cleanupdb != NULL) {
			backend->cleanupdb();
		}
	}

	close_backend();
}

bool starttrans()
{
	struct dynamic_backend *backend;
	backend = get_backend();

	if (!backend_loaded()) {
		load_backend();
	}
	
	if (backend->loaded) {
		if (backend->starttrans != NULL) {
			return backend->starttrans();
		}
	}

	return false;
}

void endtrans()
{
	struct dynamic_backend *backend;
	backend = get_backend();

	if (!backend_loaded()) {
		load_backend();
	}
	
	if (backend->loaded) {
		if (backend->endtrans != NULL) {
			backend->endtrans();
		}
	}
}

int fetch_key(uint64_t keyid, struct openpgp_publickey **publickey,
		bool intrans)
{
	struct dynamic_backend *backend;
	backend = get_backend();

	if (!backend_loaded()) {
		load_backend();
	}
	
	if (backend->loaded) {
		if (backend->fetch_key != NULL) {
			return backend->fetch_key(keyid,publickey,intrans);
		}
	}

	return -1;
}

int store_key(struct openpgp_publickey *publickey, bool intrans, bool update)
{
	struct dynamic_backend *backend;
	backend = get_backend();

	if (!backend_loaded()) {
		load_backend();
	}
	
	if (backend->loaded) {
		if (backend->store_key != NULL) {
			return backend->store_key(publickey,intrans,update);
		}
	}

	return -1;
}

int delete_key(uint64_t keyid, bool intrans)
{
	struct dynamic_backend *backend;
	backend = get_backend();

	if (!backend_loaded()) {
		load_backend();
	}
	
	if (backend->loaded) {
		if (backend->delete_key != NULL) {
			return backend->delete_key(keyid, intrans);
		}
	}

	return -1;
}

int fetch_key_text(const char *search, struct openpgp_publickey **publickey)
{
	struct dynamic_backend *backend;
	backend = get_backend();

	if (!backend_loaded()) {
		load_backend();
	}
	
	if (backend->loaded) {
		if (backend->fetch_key_text != NULL) {
			return backend->fetch_key_text(search, publickey);
		}
	}

	return -1;
}

int iterate_keys(void (*iterfunc)(void *ctx, struct openpgp_publickey *key),
		void *ctx)
{
	struct dynamic_backend *backend;
	backend = get_backend();

	if (!backend_loaded()) {
		load_backend();
	}
	
	if (backend->loaded) {
		if (backend->iterate_keys != NULL) {
			return backend->iterate_keys(iterfunc, ctx);
		}
	}

	return -1;
}
