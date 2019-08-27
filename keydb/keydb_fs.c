/*
 * keydb_fs.c - Routines to store and fetch keys in a filesystem hierarchy.
 *
 * Copyright 2004 Daniel Silverstone <dsilvers@digital-scurf.org>
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

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>

#include "charfuncs.h"
#include "decodekey.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "ll.h"
#include "mem.h"
#include "onak.h"
#include "onak-conf.h"
#include "parsekey.h"
#include "log.h"
#include "wordlist.h"

/* Hack: We should really dynamically allocate our path buffers */
#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

struct onak_fs_dbctx {
	int lockfile_fd;
	bool lockfile_readonly;
};

/*****************************************************************************/

/* Helper functions */

#define FNV_offset_basis 2166136261ul
#define FNV_mixing_prime 16777619ul

static uint32_t calchash(uint8_t * ptr)
{
	register uint32_t h = FNV_offset_basis;
	register uint32_t p = FNV_mixing_prime;
	register uint32_t n = strlen((char *) ptr);
	register uint8_t *c = ptr;
	while (n--) {
		h *= p;
		h ^= *c++;
	}
	return h ? h : 1;	/* prevent a hash of zero happening */
}


static void keypath(char *buffer, size_t length, uint64_t _keyid,
		char *basepath)
{
	uint64_t keyid = _keyid << 32;
	snprintf(buffer, length, "%s/key/%02X/%02X/%08X/%016" PRIX64,
		 basepath, (uint8_t) ((keyid >> 56) & 0xFF),
		 (uint8_t) ((keyid >> 48) & 0xFF),
		 (uint32_t) (keyid >> 32), _keyid);
}

static void keydir(char *buffer, size_t length, uint64_t _keyid,
		char *basepath)
{
	uint64_t keyid = _keyid << 32;
	snprintf(buffer, length, "%s/key/%02X/%02X/%08X", basepath,
		 (uint8_t) ((keyid >> 56) & 0xFF),
		 (uint8_t) ((keyid >> 48) & 0xFF),
		 (uint32_t) (keyid >> 32));
}

static void prove_path_to(uint64_t keyid, char *what, char *basepath)
{
	static char buffer[PATH_MAX];
	snprintf(buffer, sizeof(buffer), "%s/%s", basepath, what);
	mkdir(buffer, 0777);

	snprintf(buffer, sizeof(buffer), "%s/%s/%02X", basepath, what,
		 (uint8_t) ((keyid >> 24) & 0xFF));
	mkdir(buffer, 0777);

	snprintf(buffer, sizeof(buffer), "%s/%s/%02X/%02X", basepath,
		 what,
		 (uint8_t) ((keyid >> 24) & 0xFF),
		 (uint8_t) ((keyid >> 16) & 0xFF));
	mkdir(buffer, 0777);

	snprintf(buffer, sizeof(buffer), "%s/%s/%02X/%02X/%08X", basepath,
		 what,
		 (uint8_t) ((keyid >> 24) & 0xFF),
		 (uint8_t) ((keyid >> 16) & 0xFF), (uint32_t) (keyid));
	mkdir(buffer, 0777);
}

static void wordpath(char *buffer, size_t length, char *word, uint32_t hash,
		uint64_t keyid, char *basepath)
{
	snprintf(buffer, length, "%s/words/%02X/%02X/%08X/%s/%016" PRIX64,
		 basepath, (uint8_t) ((hash >> 24) & 0xFF),
		 (uint8_t) ((hash >> 16) & 0xFF), hash, word, keyid);
}

static void worddir(char *buffer, size_t length, char *word, uint32_t hash,
		char *basepath)
{
	snprintf(buffer, length, "%s/words/%02X/%02X/%08X/%s", basepath,
		 (uint8_t) ((hash >> 24) & 0xFF),
		 (uint8_t) ((hash >> 16) & 0xFF), hash, word);
}

static void subkeypath(char *buffer, size_t length, uint64_t subkey,
		char *basepath)
{
	snprintf(buffer, length, "%s/subkeys/%02X/%02X/%08X/%016" PRIX64,
		 basepath,
		 (uint8_t) ((subkey >> 24) & 0xFF),
		 (uint8_t) ((subkey >> 16) & 0xFF),
		 (uint32_t) (subkey & 0xFFFFFFFF),
		 subkey);
}

static void subkeydir(char *buffer, size_t length, uint64_t subkey,
		char *basepath)
{
	snprintf(buffer, length, "%s/subkeys/%02X/%02X/%08X",
		 basepath,
		 (uint8_t) ((subkey >> 24) & 0xFF),
		 (uint8_t) ((subkey >> 16) & 0xFF),
		 (uint32_t) (subkey & 0xFFFFFFFF));
}

static void skshashpath(char *buffer, size_t length,
		const struct skshash *hash, char *basepath)
{
	snprintf(buffer, length, "%s/skshash/%02X/%02X/%02X%02X%02X%02X/"
		"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
		 basepath,
		 hash->hash[0], hash->hash[1],
		 hash->hash[0], hash->hash[1], hash->hash[2], hash->hash[3],
		 hash->hash[4], hash->hash[5], hash->hash[6], hash->hash[7],
		 hash->hash[8], hash->hash[9], hash->hash[10], hash->hash[11],
		 hash->hash[12], hash->hash[13], hash->hash[14],
		 hash->hash[15]);
}

/*****************************************************************************/

/**
 *	starttrans - Start a transaction.
 */
static bool fs_starttrans(struct onak_dbctx *dbctx)
{
	struct onak_fs_dbctx *privctx = (struct onak_fs_dbctx *) dbctx->priv;
	struct flock lockstruct;
	int remaining = 20;
	lockstruct.l_type =
	    F_RDLCK | ((privctx->lockfile_readonly) ? 0 : F_WRLCK);
	lockstruct.l_whence = SEEK_SET;
	lockstruct.l_start = 0;
	lockstruct.l_len = 1;

	while (fcntl(privctx->lockfile_fd, F_SETLK, &lockstruct) == -1) {
		if (remaining-- == 0)
			return false;	/* Hope to hell that noodles DTRT */
		usleep(100);
	}
	return true;
}

/**
 *	endtrans - End a transaction.
 */
static void fs_endtrans(struct onak_dbctx *dbctx)
{
	struct onak_fs_dbctx *privctx = (struct onak_fs_dbctx *) dbctx->priv;
	struct flock lockstruct;

	lockstruct.l_type = F_UNLCK;
	lockstruct.l_whence = SEEK_SET;
	lockstruct.l_start = 0;
	lockstruct.l_len = 1;
	fcntl(privctx->lockfile_fd, F_SETLK, &lockstruct);
}

static uint64_t fs_getfullkeyid(struct onak_dbctx *dbctx, uint64_t keyid)
{
	static char buffer[PATH_MAX];
	DIR *d = NULL;
	struct dirent *de = NULL;
	uint64_t ret = 0;

	keydir(buffer, sizeof(buffer), keyid, dbctx->config->location);

	d = opendir(buffer);
	if (d) {
		do {
			de = readdir(d);
			if (de && de->d_name[0] != '.') {
				ret = strtoull(de->d_name, NULL, 16);
			}
		} while (de && de->d_name[0] == '.');
		closedir(d);	
	}

	if (ret == 0) {
		subkeydir(buffer, sizeof(buffer), keyid,
			dbctx->config->location);

		d = opendir(buffer);
		if (d) {
			do {
				de = readdir(d);
				if (de && de->d_name[0] != '.') {
					ret = strtoull(de->d_name, NULL, 16);
				}
			} while (de && de->d_name[0] == '.');
			closedir(d);
		}
	}

	return ret;
}

/**
 *	fetch_key - Given a keyid fetch the key from storage.
 *	@keyid: The keyid to fetch.
 *	@publickey: A pointer to a structure to return the key in.
 *	@intrans: If we're already in a transaction.
 */
static int fs_fetch_key_id(struct onak_dbctx *dbctx,
	      uint64_t keyid,
	      struct openpgp_publickey **publickey,
	      bool intrans)
{
	static char buffer[PATH_MAX];
	int ret = 0, fd;
	struct openpgp_packet_list *packets = NULL;

	if (!intrans)
		fs_starttrans(dbctx);

	if ((keyid >> 32) == 0)
		keyid = fs_getfullkeyid(dbctx, keyid);

	keypath(buffer, sizeof(buffer), keyid, dbctx->config->location);
	fd = open(buffer, O_RDONLY);
	if (fd == -1 && errno == ENOENT) {
		subkeypath(buffer, sizeof(buffer), keyid,
			dbctx->config->location);
		fd = open(buffer, O_RDONLY);
	}

	if (fd != -1) {
		/* File is present, load it in... */
		read_openpgp_stream(file_fetchchar, &fd, &packets, 0);
		parse_keys(packets, publickey);
		free_packet_list(packets);
		packets = NULL;
		close(fd);
		ret = 1;
	}

	if (!intrans)
		fs_endtrans(dbctx);
	return ret;
}

/**
 *	store_key - Takes a key and stores it.
 *	@publickey: A pointer to the public key to store.
 *	@intrans: If we're already in a transaction.
 *	@update: If true the key exists and should be updated.
 */
static int fs_store_key(struct onak_dbctx *dbctx,
	      struct openpgp_publickey *publickey, bool intrans,
	      bool update)
{
	static char buffer[PATH_MAX];
	static char wbuffer[PATH_MAX];
	int ret = 0, fd;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct openpgp_publickey *next = NULL;
	uint64_t keyid;
	struct ll *wordlist = NULL, *wl = NULL;
	struct skshash hash;
	struct openpgp_fingerprint *subkeyids = NULL;
	uint32_t hashid;
	int i = 0;

	if (get_keyid(publickey, &keyid) != ONAK_E_OK) {
		logthing(LOGTHING_ERROR, "Couldn't find key ID for key.");
		return 0;
	}

	if (!intrans)
		fs_starttrans(dbctx);

	prove_path_to(keyid, "key", dbctx->config->location);
	keypath(buffer, sizeof(buffer), keyid, dbctx->config->location);

	if ((fd =
	     open(buffer, O_WRONLY | (update ? O_TRUNC : O_CREAT),
		  0644)) != -1) {
		next = publickey->next;
		publickey->next = NULL;
		flatten_publickey(publickey, &packets, &list_end);
		publickey->next = next;

		write_openpgp_stream(file_putchar, &fd, packets);
		close(fd);
		free_packet_list(packets);
		packets = NULL;
		ret = 1;
	}

	if (ret) {
		wl = wordlist = makewordlistfromkey(wordlist, publickey);
		while (wl) {
			uint32_t hash = calchash((uint8_t *) (wl->object));
			prove_path_to(hash, "words", dbctx->config->location);

			worddir(wbuffer, sizeof(wbuffer), wl->object, hash,
				dbctx->config->location);
			mkdir(wbuffer, 0777);
			wordpath(wbuffer, sizeof(wbuffer), wl->object, hash,
				keyid, dbctx->config->location);
			link(buffer, wbuffer);

			wl = wl->next;
		}
		llfree(wordlist, free);
		
		subkeyids = keysubkeys(publickey);
		i = 0;
		while (subkeyids != NULL && subkeyids[i].length != 0) {
			keyid = fingerprint2keyid(&subkeyids[i]);

			prove_path_to(keyid, "subkeys",
				dbctx->config->location);

			subkeydir(wbuffer, sizeof(wbuffer), keyid,
				dbctx->config->location);
			mkdir(wbuffer, 0777);
			subkeypath(wbuffer, sizeof(wbuffer), keyid,
				dbctx->config->location);
			link(buffer, wbuffer);

			i++;
		}
		if (subkeyids != NULL) {
			free(subkeyids);
			subkeyids = NULL;
		}

		get_skshash(publickey, &hash);
		hashid = hash.hash[0];
		hashid <<= 8;
		hashid |= hash.hash[1];
		hashid <<= 8;
		hashid |= hash.hash[2];
		hashid <<= 8;
		hashid |= hash.hash[3];
		prove_path_to(hashid, "skshash", dbctx->config->location);
		skshashpath(wbuffer, sizeof(wbuffer), &hash,
			dbctx->config->location);
		link(buffer, wbuffer);
	}

	if (!intrans)
		fs_endtrans(dbctx);
	return ret;
}

/**
 *	delete_key - Given a keyid delete the key from storage.
 *	@fp: The fingerprint of the key to delete.
 *	@intrans: If we're already in a transaction.
 */
static int fs_delete_key(struct onak_dbctx *dbctx,
		struct openpgp_fingerprint *fp, bool intrans)
{
	static char buffer[PATH_MAX];
	int ret;
	struct openpgp_publickey *pk = NULL;
	struct skshash hash;
	struct ll *wordlist = NULL, *wl = NULL;
	struct openpgp_fingerprint *subkeyids = NULL;
	uint64_t subkeyid;
	int i = 0;
	uint64_t keyid;

	keyid = fingerprint2keyid(fp);
	if (keyid == 0)
		return 1;

	if (!intrans)
		fs_starttrans(dbctx);

	ret = fs_fetch_key_id(dbctx, keyid, &pk, true);

	if (ret) {
		logthing(LOGTHING_DEBUG, "Wordlist for key %016" PRIX64,
			 keyid);
		wl = wordlist = makewordlistfromkey(wordlist, pk);
		logthing(LOGTHING_DEBUG,
			 "Wordlist for key %016" PRIX64 " done", keyid);
		while (wl) {
			uint32_t hash = calchash((uint8_t *) (wl->object));
			prove_path_to(hash, "words", dbctx->config->location);

			wordpath(buffer, sizeof(buffer), wl->object, hash,
				keyid, dbctx->config->location);
			unlink(buffer);

			wl = wl->next;
		}
		llfree(wordlist, free);
		wordlist = NULL;

		subkeyids = keysubkeys(pk);
		i = 0;
		while (subkeyids != NULL && subkeyids[i].length != 0) {
			subkeyid = fingerprint2keyid(&subkeyids[i]);
			prove_path_to(subkeyid, "subkeys",
				dbctx->config->location);

			subkeypath(buffer, sizeof(buffer), subkeyid,
				dbctx->config->location);
			unlink(buffer);

			i++;
		}
		if (subkeyids != NULL) {
			free(subkeyids);
			subkeyids = NULL;
		}

		get_skshash(pk, &hash);
		skshashpath(buffer, sizeof(buffer), &hash,
			dbctx->config->location);
		unlink(buffer);
	}

	keypath(buffer, sizeof(buffer), keyid, dbctx->config->location);
	unlink(buffer);

	free_publickey(pk);

	if (!intrans)
		fs_endtrans(dbctx);
	return 1;
}

static struct ll *internal_get_key_by_word(char *word, struct ll *mct,
		char *basepath)
{
	struct ll *keys = NULL;
	DIR *d = NULL;
	char buffer[PATH_MAX];
	uint32_t hash = calchash((uint8_t *) (word));
	struct dirent *de;

	worddir(buffer, sizeof(buffer), word, hash, basepath);
	d = opendir(buffer);
	logthing(LOGTHING_DEBUG, "Scanning for word %s in dir %s", word,
		 buffer);
	if (d) {
		do {
			de = readdir(d);
			if (de && de->d_name[0] != '.') {
				if ((!mct)
				    || (llfind(mct, de->d_name,
					(int (*)(const void *, const void *))
						    strcmp) !=
					NULL)) {
					logthing(LOGTHING_DEBUG,
						 "Found %s // %s", word,
						 de->d_name);
					keys =
					    lladd(keys,
						  strdup(de->d_name));
				}
			}
		} while (de);
		closedir(d);
	}

	return keys;
}

/*
 *	fetch_key_text - Trys to find the keys that contain the supplied text.
 *	@search: The text to search for.
 *	@publickey: A pointer to a structure to return the key in.
 */
static int fs_fetch_key_text(struct onak_dbctx *dbctx,
		   const char *search,
		   struct openpgp_publickey **publickey)
{
	struct ll *wordlist = NULL, *wl = NULL;
	struct ll *keylist = NULL;
	char      *searchtext = NULL;
	int addedkeys = 0;

	logthing(LOGTHING_DEBUG, "Search was '%s'", search);

	searchtext = strdup(search);
	wl = wordlist = makewordlist(wordlist, searchtext);

	keylist = internal_get_key_by_word(wordlist->object, NULL,
		dbctx->config->location);

	if (!keylist) {
		llfree(wordlist, NULL);
		free(searchtext);
		searchtext = NULL;
		return 0;
	}

	wl = wl->next;
	while (wl) {
		struct ll *nkl =
		    internal_get_key_by_word(wl->object, keylist,
			dbctx->config->location);
		if (!nkl) {
			llfree(wordlist, NULL);
			llfree(keylist, free);
			free(searchtext);
			searchtext = NULL;
			return 0;
		}
		llfree(keylist, free);
		keylist = nkl;
		wl = wl->next;
	}

	llfree(wordlist, NULL);

	/* Now add the keys... */
	wl = keylist;
	while (wl) {
		logthing(LOGTHING_DEBUG, "Adding key: %s", wl->object);
		addedkeys +=
		    fs_fetch_key_id(dbctx,
			      strtoull(wl->object, NULL, 16), publickey,
			      false);
		if (addedkeys >= config.maxkeys)
			break;
		wl = wl->next;
	}

	llfree(keylist, free);
	free(searchtext);
	searchtext = NULL;

	return addedkeys;
}

/**
 *	fetch_key_skshash - Given an SKS hash fetch the key from storage.
 *	@hash: The hash to fetch.
 *	@publickey: A pointer to a structure to return the key in.
 *	@intrans: If we're already in a transaction.
 */
static int fs_fetch_key_skshash(struct onak_dbctx *dbctx,
	      const struct skshash *hash,
	      struct openpgp_publickey **publickey)
{
	static char buffer[PATH_MAX];
	int ret = 0, fd;
	struct openpgp_packet_list *packets = NULL;

	skshashpath(buffer, sizeof(buffer), hash, dbctx->config->location);
	if ((fd = open(buffer, O_RDONLY)) != -1) {
		read_openpgp_stream(file_fetchchar, &fd, &packets, 0);
		parse_keys(packets, publickey);
		free_packet_list(packets);
		packets = NULL;
		close(fd);
		ret = 1;
	}

	return ret;
}

/**
 *	iterate_keys - call a function once for each key in the db.
 *	@iterfunc: The function to call.
 *	@ctx: A context pointer
 *
 *	Calls iterfunc once for each key in the database. ctx is passed
 *	unaltered to iterfunc. This function is intended to aid database dumps
 *	and statistic calculations.
 *
 *	Returns the number of keys we iterated over.
 */
static int fs_iterate_keys(struct onak_dbctx *dbctx,
		void (*iterfunc)(void *ctx,
		struct openpgp_publickey *key),	void *ctx)
{
	return 0;
}

/*
 * Include the basic keydb routines.
 */
#define NEED_KEYID2UID 1
#define NEED_GETKEYSIGS 1
#define NEED_UPDATEKEYS 1
#define NEED_GET_FP 1
#include "keydb.c"

/**
 *	cleanupdb - De-initialize the key database.
 */
static void fs_cleanupdb(struct onak_dbctx *dbctx)
{
	struct onak_fs_dbctx *privctx = (struct onak_fs_dbctx *) dbctx->priv;

	/* Mmmm nothing to do here? */
	close(privctx->lockfile_fd);

	free(privctx);
	dbctx->priv = NULL;
	free(dbctx);
}

/**
 *	initdb - Initialize the key database.
 */
struct onak_dbctx *keydb_fs_init(struct onak_db_config *dbcfg, bool readonly)
{
	char buffer[PATH_MAX];
	struct onak_dbctx *dbctx;
	struct onak_fs_dbctx *privctx;

	dbctx = malloc(sizeof(struct onak_dbctx));
	if (dbctx == NULL) {
		return NULL;
	}
	dbctx->config = dbcfg;
	dbctx->priv = privctx = malloc(sizeof(*privctx));
	if (privctx == NULL) {
		free(dbctx);
		return NULL;
	}

	privctx->lockfile_readonly = readonly;

	snprintf(buffer, sizeof(buffer), "%s/.lock", dbcfg->location);

	if (access(dbcfg->location, R_OK | W_OK | X_OK) == -1) {
		if (errno != ENOENT) {
			logthing(LOGTHING_CRITICAL,
				 "Unable to access keydb_fs root of '%s'. (%s)",
				 dbcfg->location, strerror(errno));
			exit(1);	/* Lacking rwx on the key dir */
		}
		mkdir(dbcfg->location, 0777);
		privctx->lockfile_fd = open(buffer, O_RDWR | O_CREAT, 0600);
	}
	if (chdir(dbcfg->location) == -1) {
		/* Shouldn't happen after the above */
		logthing(LOGTHING_CRITICAL,
			"Couldn't change to database directory: %s",
			strerror(errno));
		free(dbctx->priv);
		free(dbctx);
		return NULL;
	}
	privctx->lockfile_fd = open(buffer,
				 (privctx->lockfile_readonly) ?
				 O_RDONLY : O_RDWR);
	if (privctx->lockfile_fd == -1)
		privctx->lockfile_fd = open(buffer, O_RDWR | O_CREAT, 0600);
	if (privctx->lockfile_fd == -1) {
		logthing(LOGTHING_CRITICAL,
			 "Unable to open lockfile '%s'. (%s)",
			 buffer, strerror(errno));
		exit(1);	/* Lacking rwx on the key dir */
	}

	dbctx->cleanupdb		= fs_cleanupdb;
	dbctx->starttrans		= fs_starttrans;
	dbctx->endtrans			= fs_endtrans;
	dbctx->fetch_key_id		= fs_fetch_key_id;
	dbctx->fetch_key_fp		= generic_fetch_key_fp;
	dbctx->fetch_key_text		= fs_fetch_key_text;
	dbctx->fetch_key_skshash	= fs_fetch_key_skshash;
	dbctx->store_key		= fs_store_key;
	dbctx->update_keys		= generic_update_keys;
	dbctx->delete_key		= fs_delete_key;
	dbctx->getkeysigs		= generic_getkeysigs;
	dbctx->cached_getkeysigs	= generic_cached_getkeysigs;
	dbctx->keyid2uid		= generic_keyid2uid;
	dbctx->iterate_keys		= fs_iterate_keys;

	return dbctx;
}
