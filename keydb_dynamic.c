/*
 * keydb_dynamic.c - backend that can load the other backends
 *
 * Brett Parker <iDunno@sommitrealweird.co.uk>
 *
 * Copyright 2005 Project Purple
 */

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include "decodekey.h"
#include "hash.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "log.h"
#include "mem.h"
#include "merge.h"
#include "onak-conf.h"
#include "parsekey.h"
#include "sendsync.h"

static struct dbfuncs *loaded_backend = NULL;
static char *backendsoname;
static void *backend_handle;

static bool close_backend(void)
{
	loaded_backend = NULL;
	dlclose(backend_handle);
	backend_handle = NULL;

	return true;
}

static bool load_backend(void)
{
	char *soname = NULL;
	char *funcsname = NULL;

	if (loaded_backend != NULL) {
		close_backend();
		loaded_backend = NULL;
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

	backend_handle = dlopen(soname, RTLD_LAZY);
	if (backend_handle == NULL) {
		logthing(LOGTHING_CRITICAL,
				"Failed to open handle to library '%s': %s",
				soname, dlerror());
		free(soname);
		soname = NULL;
		exit(EXIT_FAILURE);
	}

	funcsname = malloc(strlen(config.db_backend)
			+ strlen("keydb_")
			+ strlen("_funcs")
			+ 1);
	sprintf(funcsname, "keydb_%s_funcs", config.db_backend);

	loaded_backend = dlsym(backend_handle, funcsname);
	free(funcsname);

	if (loaded_backend == NULL) {
		logthing(LOGTHING_CRITICAL,
				"Failed to find dbfuncs structure in library "
				"'%s' : %s", soname, dlerror());
		free(soname);
		soname = NULL;
		exit(EXIT_FAILURE);
	}
	free(soname);
	soname = NULL;

	return true;
}

static bool dynamic_starttrans()
{
	struct dynamic_backend *backend;

	if (loaded_backend == NULL) {
		load_backend();
	}
	
	if (loaded_backend != NULL) {
		if (loaded_backend->starttrans != NULL) {
			return loaded_backend->starttrans();
		}
	}

	return false;
}

static void dynamic_endtrans()
{
	struct dynamic_backend *backend;

	if (loaded_backend == NULL) {
		load_backend();
	}
	
	if (loaded_backend != NULL) {
		if (loaded_backend->endtrans != NULL) {
			loaded_backend->endtrans();
		}
	}
}

static int dynamic_fetch_key(uint64_t keyid,
		struct openpgp_publickey **publickey, bool intrans)
{
	struct dynamic_backend *backend;

	if (loaded_backend == NULL) {
		load_backend();
	}
	
	if (loaded_backend != NULL) {
		if (loaded_backend->fetch_key != NULL) {
			return loaded_backend->fetch_key(keyid,publickey,intrans);
		}
	}

	return -1;
}

static int dynamic_store_key(struct openpgp_publickey *publickey, bool intrans,
		bool update)
{
	struct dynamic_backend *backend;

	if (loaded_backend == NULL) {
		load_backend();
	}
	
	if (loaded_backend != NULL) {
		if (loaded_backend->store_key != NULL) {
			return loaded_backend->store_key(publickey,intrans,update);
		}
	}

	return -1;
}

static int dynamic_delete_key(uint64_t keyid, bool intrans)
{
	struct dynamic_backend *backend;

	if (loaded_backend == NULL) {
		load_backend();
	}
	
	if (loaded_backend != NULL) {
		if (loaded_backend->delete_key != NULL) {
			return loaded_backend->delete_key(keyid, intrans);
		}
	}

	return -1;
}

static int dynamic_fetch_key_text(const char *search,
		struct openpgp_publickey **publickey)
{
	struct dynamic_backend *backend;

	if (loaded_backend == NULL) {
		load_backend();
	}
	
	if (loaded_backend != NULL) {
		if (loaded_backend->fetch_key_text != NULL) {
			return loaded_backend->fetch_key_text(search, publickey);
		}
	}

	return -1;
}

static int dynamic_iterate_keys(void (*iterfunc)(void *ctx,
		struct openpgp_publickey *key), void *ctx)
{
	struct dynamic_backend *backend;

	if (loaded_backend == NULL) {
		load_backend();
	}
	
	if (loaded_backend != NULL) {
		if (loaded_backend->iterate_keys != NULL) {
			return loaded_backend->iterate_keys(iterfunc, ctx);
		}
	}

	return -1;
}

/**
 *	keyid2uid - Takes a keyid and returns the primary UID for it.
 *	@keyid: The keyid to lookup.
 */
static char *dynamic_keyid2uid(uint64_t keyid)
{
	struct openpgp_publickey *publickey = NULL;
	struct openpgp_signedpacket_list *curuid = NULL;
	char buf[1024];

	struct dynamic_backend *backend;
	if (loaded_backend == NULL) {
		load_backend();
	}
	
	if (loaded_backend != NULL) {
		if (loaded_backend->keyid2uid != NULL) {
			return loaded_backend->keyid2uid(keyid);
		}
	}
	
	buf[0]=0;
	if (dynamic_fetch_key(keyid, &publickey, false) && publickey != NULL) {
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
static struct ll *dynamic_getkeysigs(uint64_t keyid, bool *revoked)
{
	struct ll *sigs = NULL;
	struct openpgp_signedpacket_list *uids = NULL;
	struct openpgp_publickey *publickey = NULL;
	
	struct dynamic_backend *backend;
	if ( loaded_backend == NULL ) {
		load_backend();
	}
	
	if (loaded_backend != NULL) {
		if (loaded_backend->getkeysigs != NULL) {
			return loaded_backend->getkeysigs(keyid,revoked);
		}
	}

	dynamic_fetch_key(keyid, &publickey, false);
	
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
static struct ll *dynamic_cached_getkeysigs(uint64_t keyid)
{
	struct stats_key *key = NULL;
	struct stats_key *signedkey = NULL;
	struct ll        *cursig = NULL;
	bool		  revoked = false;
	
	struct dynamic_backend *backend;

	if (keyid == 0)  {
		return NULL;
	}
	
	if (loaded_backend == NULL) {
		load_backend();
	}
	
	if (loaded_backend != NULL) {
		if (loaded_backend->cached_getkeysigs != NULL) {
			return loaded_backend->cached_getkeysigs(keyid);
		}
	}

	key = createandaddtohash(keyid);

	if (key->gotsigs == false) {
		key->sigs = dynamic_getkeysigs(key->keyid, &revoked);
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
static uint64_t dynamic_getfullkeyid(uint64_t keyid)
{
	struct openpgp_publickey *publickey = NULL;
	struct dynamic_backend *backend;
	
	if (loaded_backend == NULL) {
		load_backend();
	}
	
	if (loaded_backend != NULL) {
		if (loaded_backend->getfullkeyid != NULL) {
			return loaded_backend->getfullkeyid(keyid);
		}
	}

	if (keyid < 0x100000000LL) {
		dynamic_fetch_key(keyid, &publickey, false);
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
static int dynamic_update_keys(struct openpgp_publickey **keys, bool sendsync)
{
	struct openpgp_publickey *curkey = NULL;
	struct openpgp_publickey *oldkey = NULL;
	struct openpgp_publickey *prev = NULL;
	struct dynamic_backend *backend;
	int newkeys = 0;
	bool intrans;
	
	if (loaded_backend == NULL) {
		load_backend();
	}
	
	if (loaded_backend != NULL) {
		if (loaded_backend->update_keys != NULL) {
			return loaded_backend->update_keys(keys, sendsync);
		}
	}

	for (curkey = *keys; curkey != NULL; curkey = curkey->next) {
		intrans = dynamic_starttrans();
		logthing(LOGTHING_INFO,
			"Fetching key 0x%llX, result: %d",
			get_keyid(curkey),
			dynamic_fetch_key(get_keyid(curkey), &oldkey, intrans));

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
				dynamic_store_key(oldkey, intrans, true);
			}
			free_publickey(oldkey);
			oldkey = NULL;
		
		} else {
			logthing(LOGTHING_INFO,
				"Storing completely new key.");
			dynamic_store_key(curkey, intrans, false);
			newkeys++;
		}
		dynamic_endtrans();
		intrans = false;
	}

	if (sendsync && keys != NULL) {
		sendkeysync(*keys);
	}

	return newkeys;
}

static void dynamic_initdb(bool readonly)
{
	struct dynamic_backend *backend;
	
	if (loaded_backend == NULL) {
		load_backend();
	}

	if (loaded_backend != NULL) {
		if (loaded_backend->initdb != NULL) {
			loaded_backend->initdb(readonly);
		}
	}
}

static void dynamic_cleanupdb(void)
{
	struct dynamic_backend *backend;

	if (loaded_backend != NULL) {
		if (loaded_backend->cleanupdb != NULL) {
			loaded_backend->cleanupdb();
		}
	}

	close_backend();
}

struct dbfuncs keydb_dynamic_funcs = {
	.initdb			= dynamic_initdb,
	.cleanupdb		= dynamic_cleanupdb,
	.starttrans		= dynamic_starttrans,
	.endtrans		= dynamic_endtrans,
	.fetch_key		= dynamic_fetch_key,
	.fetch_key_text		= dynamic_fetch_key_text,
	.store_key		= dynamic_store_key,
	.update_keys		= dynamic_update_keys,
	.delete_key		= dynamic_delete_key,
	.getkeysigs		= dynamic_getkeysigs,
	.cached_getkeysigs	= dynamic_cached_getkeysigs,
	.keyid2uid		= dynamic_keyid2uid,
	.getfullkeyid		= dynamic_getfullkeyid,
	.iterate_keys		= dynamic_iterate_keys,
};
