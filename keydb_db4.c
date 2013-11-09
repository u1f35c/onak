/*
 * keydb_db4.c - Routines to store and fetch keys in a DB4 database.
 *
 * Copyright 2002-2008 Jonathan McDowell <noodles@earth.li>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <db.h>

#include "charfuncs.h"
#include "keyarray.h"
#include "keydb.h"
#include "keyid.h"
#include "decodekey.h"
#include "keystructs.h"
#include "mem.h"
#include "log.h"
#include "onak-conf.h"
#include "parsekey.h"
#include "wordlist.h"

#define DB4_UPGRADE_FILE "db_upgrade.lck"

struct onak_db4_dbctx {
	DB_ENV *dbenv;	/* The database environment context */
	int numdbs;	/* Number of data databases in use */
	DB **dbconns;	/* Connections to the key data databases */
	DB *worddb;	/* Connection to the word lookup database */
	DB *id32db;	/* Connection to the 32 bit ID lookup database */
	DB *skshashdb;	/* Connection to the SKS hash database */
	DB *subkeydb;	/* Connection to the subkey ID lookup database */
	DB_TXN *txn;	/* Our current transaction ID */
};

DB *keydb(struct onak_db4_dbctx *privctx, uint64_t keyid)
{
	uint64_t keytrun;

	keytrun = keyid >> 8;

	return(privctx->dbconns[keytrun % privctx->numdbs]);
}

/**
 *	db4_errfunc - Direct DB errors to logfile
 *
 *	Basic function to take errors from the DB library and output them to
 *	the logfile rather than stderr.
 */
#if (DB_VERSION_MAJOR == 4) && (DB_VERSION_MINOR < 3)
static void db4_errfunc(const char *errpfx, const char *errmsg)
#else
static void db4_errfunc(const DB_ENV *edbenv, const char *errpfx,
		const char *errmsg)
#endif
{
	if (errpfx) {
		logthing(LOGTHING_DEBUG, "db4 error: %s:%s", errpfx, errmsg);
	} else {
		logthing(LOGTHING_DEBUG, "db4 error: %s", errmsg);
	}

	return;
}

/**
 *	starttrans - Start a transaction.
 *
 *	Start a transaction. Intended to be used if we're about to perform many
 *	operations on the database to help speed it all up, or if we want
 *	something to only succeed if all relevant operations are successful.
 */
static bool db4_starttrans(struct onak_dbctx *dbctx)
{
	struct onak_db4_dbctx *privctx = (struct onak_db4_dbctx *) dbctx->priv;
	int ret;

	log_assert(privctx->dbenv != NULL);
	log_assert(privctx->txn == NULL);

	ret = privctx->dbenv->txn_begin(privctx->dbenv,
		NULL, /* No parent transaction */
		&privctx->txn,
		0);
	if (ret != 0) {
		logthing(LOGTHING_CRITICAL,
				"Error starting transaction: %s",
				db_strerror(ret));
		exit(1);
	}

	return true;
}

/**
 *	endtrans - End a transaction.
 *
 *	Ends a transaction.
 */
static void db4_endtrans(struct onak_dbctx *dbctx)
{
	struct onak_db4_dbctx *privctx = (struct onak_db4_dbctx *) dbctx->priv;
	int ret;

	log_assert(privctx->dbenv != NULL);
	log_assert(privctx->txn != NULL);

	ret = privctx->txn->commit(privctx->txn,
		0);
	if (ret != 0) {
		logthing(LOGTHING_CRITICAL,
				"Error ending transaction: %s",
				db_strerror(ret));
		exit(1);
	}
	privctx->txn = NULL;

	return;
}

/**
 *	db4_upgradedb - Upgrade a DB4 database
 *
 *	Called if we discover we need to upgrade our DB4 database; ie if
 *	we're running with a newer version of db4 than the database was
 *	created with.
 */
static int db4_upgradedb(struct onak_db4_dbctx *privctx)
{
	DB *curdb = NULL;
	int ret;
	int i;
	char buf[1024];
	int lockfile_fd;
	struct stat statbuf;

	snprintf(buf, sizeof(buf) - 1, "%s/%s", config.db_dir,
			DB4_UPGRADE_FILE);
	lockfile_fd = open(buf, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (lockfile_fd < 0) {
		if (errno == EEXIST) {
			while (stat(buf, &statbuf) == 0) ;
			return 0;
		} else {
			logthing(LOGTHING_CRITICAL, "Couldn't open database "
				"update lock file: %s", strerror(errno));
			return -1;
		}
	}
	snprintf(buf, sizeof(buf) - 1, "%d", getpid());
	write(lockfile_fd, buf, strlen(buf));
	close(lockfile_fd);

	logthing(LOGTHING_NOTICE, "Upgrading DB4 database");
	ret = db_env_create(&privctx->dbenv, 0);
	if (ret == 0) {
		privctx->dbenv->set_errcall(privctx->dbenv, &db4_errfunc);
		privctx->dbenv->remove(privctx->dbenv, config.db_dir, 0);
		privctx->dbenv = NULL;
	}
	for (i = 0; i < privctx->numdbs; i++) {
		ret = db_create(&curdb, NULL, 0);
		if (ret == 0) {
			snprintf(buf, sizeof(buf) - 1, "%s/keydb.%d.db",
				config.db_dir, i);
			logthing(LOGTHING_DEBUG, "Upgrading %s", buf);
			curdb->upgrade(curdb, buf, 0);
			curdb->close(curdb, 0);
		} else {
			logthing(LOGTHING_ERROR, "Error upgrading DB %s : %s",
				buf,
				db_strerror(ret));
		}
	}

	ret = db_create(&curdb, NULL, 0);
	if (ret == 0) {
		snprintf(buf, sizeof(buf) - 1, "%s/worddb", config.db_dir);
		logthing(LOGTHING_DEBUG, "Upgrading %s", buf);
		curdb->upgrade(curdb, buf, 0);
		curdb->close(curdb, 0);
	} else {
		logthing(LOGTHING_ERROR, "Error upgrading DB %s : %s",
			buf,
			db_strerror(ret));
	}

	ret = db_create(&curdb, NULL, 0);
	if (ret == 0) {
		snprintf(buf, sizeof(buf) - 1, "%s/id32db", config.db_dir);
		logthing(LOGTHING_DEBUG, "Upgrading %s", buf);
		curdb->upgrade(curdb, buf, 0);
		curdb->close(curdb, 0);
	} else {
		logthing(LOGTHING_ERROR, "Error upgrading DB %s : %s",
			buf,
			db_strerror(ret));
	}

	ret = db_create(&curdb, NULL, 0);
	if (ret == 0) {
		snprintf(buf, sizeof(buf) - 1, "%s/skshashdb", config.db_dir);
		logthing(LOGTHING_DEBUG, "Upgrading %s", buf);
		curdb->upgrade(curdb, buf, 0);
		curdb->close(curdb, 0);
	} else {
		logthing(LOGTHING_ERROR, "Error upgrading DB %s : %s",
			buf,
			db_strerror(ret));
	}

	ret = db_create(&curdb, NULL, 0);
	if (ret == 0) {
		snprintf(buf, sizeof(buf) - 1, "%s/subkeydb", config.db_dir);
		logthing(LOGTHING_DEBUG, "Upgrading %s", buf);
		curdb->upgrade(curdb, buf, 0);
		curdb->close(curdb, 0);
	} else {
		logthing(LOGTHING_ERROR, "Error upgrading DB %s : %s",
			buf,
			db_strerror(ret));
	}

	snprintf(buf, sizeof(buf) - 1, "%s/%s", config.db_dir,
			DB4_UPGRADE_FILE);
	unlink(buf);

	return ret;
}

/**
 *	getfullkeyid - Maps a 32bit key id to a 64bit one.
 *	@keyid: The 32bit keyid.
 *
 *	This function maps a 32bit key id to the full 64bit one. It returns the
 *	full keyid. If the key isn't found a keyid of 0 is returned.
 */
static uint64_t db4_getfullkeyid(struct onak_dbctx *dbctx, uint64_t keyid)
{
	struct onak_db4_dbctx *privctx = (struct onak_db4_dbctx *) dbctx->priv;
	DBT       key, data;
	DBC      *cursor = NULL;
	uint32_t  shortkeyid = 0;
	int       ret = 0;

	if (keyid < 0x100000000LL) {
		ret = privctx->id32db->cursor(privctx->id32db,
				privctx->txn,
				&cursor,
				0);   /* flags */

		if (ret != 0) {
			return 0;
		}

		shortkeyid = keyid & 0xFFFFFFFF;

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
		key.data = &shortkeyid;
		key.size = sizeof(shortkeyid);
		data.flags = DB_DBT_MALLOC;

		ret = cursor->c_get(cursor,
			&key,
			&data,
			DB_SET);

		if (ret == 0) {
			keyid = *(uint64_t *) data.data;

			if (data.data != NULL) {
				free(data.data);
				data.data = NULL;
			}
		}

		cursor->c_close(cursor);
		cursor = NULL;
	}

	return keyid;
}

/**
 *	fetch_key_id - Given a keyid fetch the key from storage.
 *	@keyid: The keyid to fetch.
 *	@publickey: A pointer to a structure to return the key in.
 *	@intrans: If we're already in a transaction.
 *
 *	We use the hex representation of the keyid as the filename to fetch the
 *	key from. The key is stored in the file as a binary OpenPGP stream of
 *	packets, so we can just use read_openpgp_stream() to read the packets
 *	in and then parse_keys() to parse the packets into a publickey
 *	structure.
 */
static int db4_fetch_key_id(struct onak_dbctx *dbctx, uint64_t keyid,
		struct openpgp_publickey **publickey,
		bool intrans)
{
	struct onak_db4_dbctx *privctx = (struct onak_db4_dbctx *) dbctx->priv;
	struct openpgp_packet_list *packets = NULL;
	DBT key, data;
	int ret = 0;
	int numkeys = 0;
	struct buffer_ctx fetchbuf;

	if (keyid < 0x100000000LL) {
		keyid = db4_getfullkeyid(dbctx, keyid);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	data.size = 0;
	data.data = NULL;

	key.size = sizeof(keyid);
	key.data = &keyid;

	if (!intrans) {
		db4_starttrans(dbctx);
	}

	ret = keydb(privctx, keyid)->get(keydb(privctx, keyid),
			privctx->txn,
			&key,
			&data,
			0); /* flags*/

	if (ret == DB_NOTFOUND) {
		/* If we didn't find the key ID see if it's a subkey ID */
		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
		data.size = 0;
		data.data = NULL;
		key.size = sizeof(keyid);
		key.data = &keyid;

		ret = privctx->subkeydb->get(privctx->subkeydb,
			privctx->txn,
			&key,
			&data,
			0); /* flags*/

		if (ret == 0) {
			/* We got a subkey match; retrieve the actual key */
			keyid = *(uint64_t *) data.data;

			memset(&key, 0, sizeof(key));
			memset(&data, 0, sizeof(data));
			data.size = 0;
			data.data = NULL;
			key.size = sizeof(keyid);
			key.data = &keyid;

			ret = keydb(privctx, keyid)->get(keydb(privctx, keyid),
				privctx->txn,
				&key,
				&data,
				0); /* flags*/
		}
	}

	if (ret == 0) {
		fetchbuf.buffer = data.data;
		fetchbuf.offset = 0;
		fetchbuf.size = data.size;
		read_openpgp_stream(buffer_fetchchar, &fetchbuf,
				&packets, 0);
		parse_keys(packets, publickey);
		free_packet_list(packets);
		packets = NULL;
		numkeys++;
	} else if (ret != DB_NOTFOUND) {
		logthing(LOGTHING_ERROR,
				"Problem retrieving key: %s",
				db_strerror(ret));
	}

	if (!intrans) {
		db4_endtrans(dbctx);
	}

	return (numkeys);
}

int worddb_cmp(const void *d1, const void *d2)
{
	return memcmp(d1, d2, 12);
}

/**
 *	fetch_key_text - Trys to find the keys that contain the supplied text.
 *	@search: The text to search for.
 *	@publickey: A pointer to a structure to return the key in.
 *
 *	This function searches for the supplied text and returns the keys that
 *	contain it.
 */
static int db4_fetch_key_text(struct onak_dbctx *dbctx, const char *search,
		struct openpgp_publickey **publickey)
{
	struct onak_db4_dbctx *privctx = (struct onak_db4_dbctx *) dbctx->priv;
	DBC *cursor = NULL;
	DBT key, data;
	int ret;
	uint64_t keyid;
	int i;
	int numkeys;
	char *searchtext = NULL;
	struct ll *wordlist = NULL;
	struct ll *curword = NULL;
	struct keyarray keylist = { NULL, 0, 0 };
	struct keyarray newkeylist = { NULL, 0, 0 };
	int firstpass = 1;

	numkeys = 0;
	searchtext = strdup(search);
	wordlist = makewordlist(wordlist, searchtext);

	for (curword = wordlist; curword != NULL; curword = curword->next) {
		db4_starttrans(dbctx);

		ret = privctx->worddb->cursor(privctx->worddb,
				privctx->txn,
				&cursor,
				0);   /* flags */

		if (ret != 0) {
			db4_endtrans(dbctx);
			break;
		}

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
		key.data = curword->object;
		key.size = strlen(curword->object);
		data.flags = DB_DBT_MALLOC;
		ret = cursor->c_get(cursor,
				&key,
				&data,
				DB_SET);
		while (ret == 0 && strncmp(key.data, curword->object,
					key.size) == 0 &&
				((char *) curword->object)[key.size] == 0) {
			keyid = 0;
			for (i = 4; i < 12; i++) {
				keyid <<= 8;
				keyid += ((unsigned char *)
						data.data)[i];
			}

			/*
			 * Only add the keys containing this word if this is
			 * our first pass (ie we have no existing key list),
			 * or the key contained a previous word.
			 */
			if (firstpass || array_find(&keylist, keyid)) {
				array_add(&newkeylist, keyid);
			}

			free(data.data);
			data.data = NULL;

			ret = cursor->c_get(cursor,
					&key,
					&data,
					DB_NEXT);
		}
		array_free(&keylist);
		keylist = newkeylist;
		newkeylist.keys = NULL;
		newkeylist.count = newkeylist.size = 0;
		if (data.data != NULL) {
			free(data.data);
			data.data = NULL;
		}
		cursor->c_close(cursor);
		cursor = NULL;
		firstpass = 0;
		db4_endtrans(dbctx);
	}
	llfree(wordlist, NULL);
	wordlist = NULL;

	if (keylist.count > config.maxkeys) {
		keylist.count = config.maxkeys;
	}

	db4_starttrans(dbctx);
	for (i = 0; i < keylist.count; i++) {
		numkeys += db4_fetch_key_id(dbctx, keylist.keys[i],
			publickey,
			true);
	}
	array_free(&keylist);
	free(searchtext);
	searchtext = NULL;

	db4_endtrans(dbctx);

	return (numkeys);
}

static int db4_fetch_key_skshash(struct onak_dbctx *dbctx,
		const struct skshash *hash,
		struct openpgp_publickey **publickey)
{
	struct onak_db4_dbctx *privctx = (struct onak_db4_dbctx *) dbctx->priv;
	DBT       key, data;
	DBC      *cursor = NULL;
	uint64_t  keyid = 0;
	int       ret = 0;

	ret = privctx->skshashdb->cursor(privctx->skshashdb,
			privctx->txn,
			&cursor,
			0);   /* flags */

	if (ret != 0) {
		return 0;
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	key.data = (void *) hash->hash;
	key.size = sizeof(hash->hash);
	data.flags = DB_DBT_MALLOC;

	ret = cursor->c_get(cursor,
		&key,
		&data,
		DB_SET);

	if (ret == 0) {
		keyid = *(uint64_t *) data.data;

		if (data.data != NULL) {
			free(data.data);
			data.data = NULL;
		}
	}

	cursor->c_close(cursor);
	cursor = NULL;

	return db4_fetch_key_id(dbctx, keyid, publickey, false);
}

/**
 *	delete_key - Given a keyid delete the key from storage.
 *	@keyid: The keyid to delete.
 *	@intrans: If we're already in a transaction.
 *
 *	This function deletes a public key from whatever storage mechanism we
 *	are using. Returns 0 if the key existed.
 */
static int db4_delete_key(struct onak_dbctx *dbctx,
		uint64_t keyid, bool intrans)
{
	struct onak_db4_dbctx *privctx = (struct onak_db4_dbctx *) dbctx->priv;
	struct openpgp_publickey *publickey = NULL;
	DBT key, data;
	DBC *cursor = NULL;
	uint32_t   shortkeyid = 0;
	uint64_t  *subkeyids = NULL;
	int ret = 0;
	int i;
	char **uids = NULL;
	char *primary = NULL;
	unsigned char worddb_data[12];
	struct ll *wordlist = NULL;
	struct ll *curword  = NULL;
	bool deadlock = false;
	struct skshash hash;

	if (!intrans) {
		db4_starttrans(dbctx);
	}

	db4_fetch_key_id(dbctx, keyid, &publickey, true);

	/*
	 * Walk through the uids removing the words from the worddb.
	 */
	if (publickey != NULL) {
		uids = keyuids(publickey, &primary);
	}
	if (uids != NULL) {
		for (i = 0; ret == 0 && uids[i] != NULL; i++) {
			wordlist = makewordlist(wordlist, uids[i]);
		}

		privctx->worddb->cursor(privctx->worddb,
			privctx->txn,
			&cursor,
			0);   /* flags */

		for (curword = wordlist; curword != NULL && !deadlock;
				curword = curword->next) {
			memset(&key, 0, sizeof(key));
			memset(&data, 0, sizeof(data));
			key.data = curword->object;
			key.size = strlen(key.data);
			data.data = worddb_data;
			data.size = sizeof(worddb_data);

			/*
			 * Our data is the key creation time followed by the
			 * key id.
			 */
			worddb_data[ 0] = publickey->publickey->data[1];
			worddb_data[ 1] = publickey->publickey->data[2];
			worddb_data[ 2] = publickey->publickey->data[3];
			worddb_data[ 3] = publickey->publickey->data[4];
			worddb_data[ 4] = (keyid >> 56) & 0xFF;
			worddb_data[ 5] = (keyid >> 48) & 0xFF;
			worddb_data[ 6] = (keyid >> 40) & 0xFF;
			worddb_data[ 7] = (keyid >> 32) & 0xFF;
			worddb_data[ 8] = (keyid >> 24) & 0xFF;
			worddb_data[ 9] = (keyid >> 16) & 0xFF;
			worddb_data[10] = (keyid >>  8) & 0xFF;
			worddb_data[11] = keyid & 0xFF;

			ret = cursor->c_get(cursor,
				&key,
				&data,
				DB_GET_BOTH);

			if (ret == 0) {
				ret = cursor->c_del(cursor, 0);
			}

			if (ret != 0) {
				logthing(LOGTHING_ERROR,
					"Problem deleting word: %s "
					"(0x%016" PRIX64 ")",
					db_strerror(ret),
					keyid);
				if (ret == DB_LOCK_DEADLOCK) {
					deadlock = true;
				}
			}
		}
		cursor->c_close(cursor);
		cursor = NULL;

		ret = privctx->skshashdb->cursor(privctx->skshashdb,
			privctx->txn,
			&cursor,
			0);   /* flags */
		if (ret == 0) {
			get_skshash(publickey, &hash);

			memset(&key, 0, sizeof(key));
			memset(&data, 0, sizeof(data));
			key.data = hash.hash;
			key.size = sizeof(hash.hash);
			data.data = &keyid;
			data.size = sizeof(keyid);

			ret = cursor->c_get(cursor,
				&key,
				&data,
				DB_GET_BOTH);

			if (ret == 0) {
				ret = cursor->c_del(cursor, 0);
			}

			if (ret != 0) {
				logthing(LOGTHING_ERROR,
					"Problem deleting skshash: %s "
					"(0x%016" PRIX64 ")",
					db_strerror(ret),
					keyid);
				if (ret == DB_LOCK_DEADLOCK) {
					deadlock = true;
				}
			}

			cursor->c_close(cursor);
			cursor = NULL;
		}

		/*
		 * Free our UID and word lists.
		 */
		llfree(wordlist, NULL);
		for (i = 0; uids[i] != NULL; i++) {
			free(uids[i]);
			uids[i] = NULL;
		}
		free(uids);
		uids = NULL;
		free_publickey(publickey);
		publickey = NULL;
	}

	if (!deadlock) {
		privctx->id32db->cursor(privctx->id32db,
			privctx->txn,
			&cursor,
			0);   /* flags */

		shortkeyid = keyid & 0xFFFFFFFF;

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
		key.data = &shortkeyid;
		key.size = sizeof(shortkeyid);
		data.data = &keyid;
		data.size = sizeof(keyid);

		ret = cursor->c_get(cursor,
			&key,
			&data,
			DB_GET_BOTH);

		if (ret == 0) {
			ret = cursor->c_del(cursor, 0);
		}

		if (ret != 0) {
			logthing(LOGTHING_ERROR,
				"Problem deleting short keyid: %s "
				"(0x%016" PRIX64 ")",
				db_strerror(ret),
				keyid);
			if (ret == DB_LOCK_DEADLOCK) {
				deadlock = true;
			}
		}

		subkeyids = keysubkeys(publickey);
		i = 0;
		while (subkeyids != NULL && subkeyids[i] != 0) {
			memset(&key, 0, sizeof(key));
			key.data = &subkeyids[i];
			key.size = sizeof(subkeyids[i]);
			privctx->subkeydb->del(privctx->subkeydb,
					privctx->txn, &key, 0);
			if (ret != 0) {
				logthing(LOGTHING_ERROR,
					"Problem deleting subkey id: %s "
					"(0x%016" PRIX64 ")",
					db_strerror(ret),
					keyid);
				if (ret == DB_LOCK_DEADLOCK) {
					deadlock = true;
				}
			}

			shortkeyid = subkeyids[i++] & 0xFFFFFFFF;

			memset(&key, 0, sizeof(key));
			memset(&data, 0, sizeof(data));
			key.data = &shortkeyid;
			key.size = sizeof(shortkeyid);
			data.data = &keyid;
			data.size = sizeof(keyid);

			ret = cursor->c_get(cursor,
				&key,
				&data,
				DB_GET_BOTH);

			if (ret == 0) {
				ret = cursor->c_del(cursor, 0);
			}

			if (ret != 0) {
				logthing(LOGTHING_ERROR,
					"Problem deleting short keyid: %s "
					"(0x%016" PRIX64 ")",
					db_strerror(ret),
					keyid);
				if (ret == DB_LOCK_DEADLOCK) {
					deadlock = true;
				}
			}
		}
		if (subkeyids != NULL) {
			free(subkeyids);
			subkeyids = NULL;
		}
		cursor->c_close(cursor);
		cursor = NULL;
	}

	if (!deadlock) {
		key.data = &keyid;
		key.size = sizeof(keyid);

		keydb(privctx, keyid)->del(keydb(privctx, keyid),
				privctx->txn,
				&key,
				0); /* flags */
	}

	if (!intrans) {
		db4_endtrans(dbctx);
	}

	return deadlock ? (-1) : (ret == DB_NOTFOUND);
}

/**
 *	store_key - Takes a key and stores it.
 *	@publickey: A pointer to the public key to store.
 *	@intrans: If we're already in a transaction.
 *	@update: If true the key exists and should be updated.
 *
 *	Again we just use the hex representation of the keyid as the filename
 *	to store the key to. We flatten the public key to a list of OpenPGP
 *	packets and then use write_openpgp_stream() to write the stream out to
 *	the file. If update is true then we delete the old key first, otherwise
 *	we trust that it doesn't exist.
 */
static int db4_store_key(struct onak_dbctx *dbctx,
		struct openpgp_publickey *publickey, bool intrans,
		bool update)
{
	struct onak_db4_dbctx *privctx = (struct onak_db4_dbctx *) dbctx->priv;
	struct     openpgp_packet_list *packets = NULL;
	struct     openpgp_packet_list *list_end = NULL;
	struct     openpgp_publickey *next = NULL;
	int        ret = 0;
	int        i = 0;
	struct     buffer_ctx storebuf;
	DBT        key;
	DBT        data;
	uint64_t   keyid = 0;
	uint32_t   shortkeyid = 0;
	uint64_t  *subkeyids = NULL;
	char     **uids = NULL;
	char      *primary = NULL;
	unsigned char worddb_data[12];
	struct ll *wordlist = NULL;
	struct ll *curword  = NULL;
	bool       deadlock = false;
	struct skshash hash;

	if (get_keyid(publickey, &keyid) != ONAK_E_OK) {
		logthing(LOGTHING_ERROR, "Couldn't find key ID for key.");
		return 0;
	}

	if (!intrans) {
		db4_starttrans(dbctx);
	}

	/*
	 * Delete the key if we already have it.
	 *
	 * TODO: Can we optimize this perhaps? Possibly when other data is
	 * involved as well? I suspect this is easiest and doesn't make a lot
	 * of difference though - the largest chunk of data is the keydata and
	 * it definitely needs updated.
	 */
	if (update) {
		deadlock = (db4_delete_key(dbctx, keyid, true) == -1);
	}

	/*
	 * Convert the key to a flat set of binary data.
	 */
	if (!deadlock) {
		next = publickey->next;
		publickey->next = NULL;
		flatten_publickey(publickey, &packets, &list_end);
		publickey->next = next;

		storebuf.offset = 0;
		storebuf.size = 8192;
		storebuf.buffer = malloc(8192);

		write_openpgp_stream(buffer_putchar, &storebuf, packets);

		/*
		 * Now we have the key data store it in the DB; the keyid is
		 * the key.
		 */
		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
		key.data = &keyid;
		key.size = sizeof(keyid);
		data.size = storebuf.offset;
		data.data = storebuf.buffer;

		ret = keydb(privctx, keyid)->put(keydb(privctx, keyid),
				privctx->txn,
				&key,
				&data,
				0); /* flags*/
		if (ret != 0) {
			logthing(LOGTHING_ERROR,
					"Problem storing key: %s",
					db_strerror(ret));
			if (ret == DB_LOCK_DEADLOCK) {
				deadlock = true;
			}
		}

		free(storebuf.buffer);
		storebuf.buffer = NULL;
		storebuf.size = 0;
		storebuf.offset = 0;

		free_packet_list(packets);
		packets = NULL;
	}

	/*
	 * Walk through our uids storing the words into the db with the keyid.
	 */
	if (!deadlock) {
		uids = keyuids(publickey, &primary);
	}
	if (uids != NULL) {
		for (i = 0; ret == 0 && uids[i] != NULL; i++) {
			wordlist = makewordlist(wordlist, uids[i]);
		}

		for (curword = wordlist; curword != NULL && !deadlock;
				curword = curword->next) {
			memset(&key, 0, sizeof(key));
			memset(&data, 0, sizeof(data));
			key.data = curword->object;
			key.size = strlen(key.data);
			data.data = worddb_data;
			data.size = sizeof(worddb_data);

			/*
			 * Our data is the key creation time followed by the
			 * key id.
			 */
			worddb_data[ 0] = publickey->publickey->data[1];
			worddb_data[ 1] = publickey->publickey->data[2];
			worddb_data[ 2] = publickey->publickey->data[3];
			worddb_data[ 3] = publickey->publickey->data[4];
			worddb_data[ 4] = (keyid >> 56) & 0xFF;
			worddb_data[ 5] = (keyid >> 48) & 0xFF;
			worddb_data[ 6] = (keyid >> 40) & 0xFF;
			worddb_data[ 7] = (keyid >> 32) & 0xFF;
			worddb_data[ 8] = (keyid >> 24) & 0xFF;
			worddb_data[ 9] = (keyid >> 16) & 0xFF;
			worddb_data[10] = (keyid >>  8) & 0xFF;
			worddb_data[11] = keyid & 0xFF;
			ret = privctx->worddb->put(privctx->worddb,
				privctx->txn,
				&key,
				&data,
				0);
			if (ret != 0) {
				logthing(LOGTHING_ERROR,
					"Problem storing word: %s",
					db_strerror(ret));
				if (ret == DB_LOCK_DEADLOCK) {
					deadlock = true;
				}
			}
		}

		/*
		 * Free our UID and word lists.
		 */
		llfree(wordlist, NULL);
		for (i = 0; uids[i] != NULL; i++) {
			free(uids[i]);
			uids[i] = NULL;
		}
		free(uids);
		uids = NULL;
	}

	/*
	 * Write the truncated 32 bit keyid so we can lookup the full id for
	 * queries.
	 */
	if (!deadlock) {
		shortkeyid = keyid & 0xFFFFFFFF;

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
		key.data = &shortkeyid;
		key.size = sizeof(shortkeyid);
		data.data = &keyid;
		data.size = sizeof(keyid);

		ret = privctx->id32db->put(privctx->id32db,
			privctx->txn,
			&key,
			&data,
			0);
		if (ret != 0) {
			logthing(LOGTHING_ERROR,
				"Problem storing short keyid: %s",
				db_strerror(ret));
			if (ret == DB_LOCK_DEADLOCK) {
				deadlock = true;
			}
		}
	}

	if (!deadlock) {
		subkeyids = keysubkeys(publickey);
		i = 0;
		while (subkeyids != NULL && subkeyids[i] != 0) {
			/* Store the subkey ID -> main key ID mapping */
			memset(&key, 0, sizeof(key));
			memset(&data, 0, sizeof(data));
			key.data = &subkeyids[i];
			key.size = sizeof(subkeyids[i]);
			data.data = &keyid;
			data.size = sizeof(keyid);

			ret = privctx->subkeydb->put(privctx->subkeydb,
				privctx->txn,
				&key,
				&data,
				0);
			if (ret != 0) {
				logthing(LOGTHING_ERROR,
					"Problem storing subkey keyid: %s",
					db_strerror(ret));
				if (ret == DB_LOCK_DEADLOCK) {
					deadlock = true;
				}
			}

			/* Store the short subkey ID -> main key ID mapping */
			shortkeyid = subkeyids[i++] & 0xFFFFFFFF;

			memset(&key, 0, sizeof(key));
			memset(&data, 0, sizeof(data));
			key.data = &shortkeyid;
			key.size = sizeof(shortkeyid);
			data.data = &keyid;
			data.size = sizeof(keyid);

			ret = privctx->id32db->put(privctx->id32db,
				privctx->txn,
				&key,
				&data,
				0);
			if (ret != 0) {
				logthing(LOGTHING_ERROR,
					"Problem storing short keyid: %s",
					db_strerror(ret));
				if (ret == DB_LOCK_DEADLOCK) {
					deadlock = true;
				}
			}
		}
		if (subkeyids != NULL) {
			free(subkeyids);
			subkeyids = NULL;
		}
	}

	if (!deadlock) {
		get_skshash(publickey, &hash);
		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
		key.data = hash.hash;
		key.size = sizeof(hash.hash);
		data.data = &keyid;
		data.size = sizeof(keyid);

		ret = privctx->skshashdb->put(privctx->skshashdb,
			privctx->txn,
			&key,
			&data,
			0);
		if (ret != 0) {
			logthing(LOGTHING_ERROR,
				"Problem storing SKS hash: %s",
				db_strerror(ret));
			if (ret == DB_LOCK_DEADLOCK) {
				deadlock = true;
			}
		}
	}

	if (!intrans) {
		db4_endtrans(dbctx);
	}

	return deadlock ? -1 : 0 ;
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
static int db4_iterate_keys(struct onak_dbctx *dbctx,
		void (*iterfunc)(void *ctx, struct openpgp_publickey *key),
		void *ctx)
{
	struct onak_db4_dbctx *privctx = (struct onak_db4_dbctx *) dbctx->priv;
	DBT                         dbkey, data;
	DBC                        *cursor = NULL;
	int                         ret = 0;
	int                         i = 0;
	int                         numkeys = 0;
	struct buffer_ctx           fetchbuf;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_publickey   *key = NULL;

	for (i = 0; i < privctx->numdbs; i++) {
		ret = privctx->dbconns[i]->cursor(privctx->dbconns[i],
			NULL,
			&cursor,
			0);   /* flags */

		if (ret != 0) {
			continue;
		}

		memset(&dbkey, 0, sizeof(dbkey));
		memset(&data, 0, sizeof(data));
		ret = cursor->c_get(cursor, &dbkey, &data, DB_NEXT);
		while (ret == 0) {
			fetchbuf.buffer = data.data;
			fetchbuf.offset = 0;
			fetchbuf.size = data.size;
			read_openpgp_stream(buffer_fetchchar, &fetchbuf,
				&packets, 0);
			parse_keys(packets, &key);

			iterfunc(ctx, key);

			free_publickey(key);
			key = NULL;
			free_packet_list(packets);
			packets = NULL;

			memset(&dbkey, 0, sizeof(dbkey));
			memset(&data, 0, sizeof(data));
			ret = cursor->c_get(cursor, &dbkey, &data,
					DB_NEXT);
			numkeys++;
		}
		if (ret != DB_NOTFOUND) {
			logthing(LOGTHING_ERROR,
				"Problem reading key: %s",
				db_strerror(ret));
		}

		cursor->c_close(cursor);
		cursor = NULL;
	}

	return numkeys;
}

/*
 * Include the basic keydb routines.
 */
#define NEED_GETKEYSIGS 1
#define NEED_KEYID2UID 1
#define NEED_UPDATEKEYS 1
#define NEED_GET_FP 1
#include "keydb.c"

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	This function should be called upon program exit to allow the DB to
 *	cleanup after itself.
 */
static void db4_cleanupdb(struct onak_dbctx *dbctx)
{
	struct onak_db4_dbctx *privctx = (struct onak_db4_dbctx *) dbctx->priv;
	int i = 0;

	if (privctx->dbenv != NULL) {
		privctx->dbenv->txn_checkpoint(privctx->dbenv, 0, 0, 0);
		if (privctx->subkeydb != NULL) {
			privctx->subkeydb->close(privctx->subkeydb, 0);
			privctx->subkeydb = NULL;
		}
		if (privctx->skshashdb != NULL) {
			privctx->skshashdb->close(privctx->skshashdb, 0);
			privctx->skshashdb = NULL;
		}
		if (privctx->id32db != NULL) {
			privctx->id32db->close(privctx->id32db, 0);
			privctx->id32db = NULL;
		}
		if (privctx->worddb != NULL) {
			privctx->worddb->close(privctx->worddb, 0);
			privctx->worddb = NULL;
		}
		for (i = 0; i < privctx->numdbs; i++) {
			if (privctx->dbconns[i] != NULL) {
				privctx->dbconns[i]->close(privctx->dbconns[i],
						0);
				privctx->dbconns[i] = NULL;
			}
		}
		free(privctx->dbconns);
		privctx->dbconns = NULL;
		privctx->dbenv->close(privctx->dbenv, 0);
		privctx->dbenv = NULL;
	}

	free(privctx);
	dbctx->priv = NULL;
	free(dbctx);
}

/**
 *	initdb - Initialize the key database.
 *
 *	This function should be called before any of the other functions in
 *	this file are called in order to allow the DB to be initialized ready
 *	for access.
 */
struct onak_dbctx *keydb_db4_init(bool readonly)
{
	char       buf[1024];
	FILE      *numdb = NULL;
	int        ret = 0;
	int        i = 0;
	uint32_t   flags = 0;
	struct stat statbuf;
	int        maxlocks;
	struct onak_dbctx *dbctx;
	struct onak_db4_dbctx *privctx;

	dbctx = malloc(sizeof(*dbctx));
	if (dbctx == NULL) {
		return NULL;
	}
	dbctx->priv = privctx = calloc(1, sizeof(*privctx));
	if (privctx == NULL) {
		free(dbctx);
		return NULL;
	}

	/* Default to 16 key data DBs */
	privctx->numdbs = 16;

	snprintf(buf, sizeof(buf) - 1, "%s/%s", config.db_dir,
			DB4_UPGRADE_FILE);
	ret = stat(buf, &statbuf);
	while ((ret == 0) || (errno != ENOENT)) {
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL, "Couldn't stat upgrade "
				"lock file: %s (%d)", strerror(errno), ret);
			exit(1);
		}
		logthing(LOGTHING_DEBUG, "DB4 upgrade in progress; waiting.");
		sleep(5);
		ret = stat(buf, &statbuf);
	}
	ret = 0;

	snprintf(buf, sizeof(buf) - 1, "%s/num_keydb", config.db_dir);
	numdb = fopen(buf, "r");
	if (numdb != NULL) {
		if (fgets(buf, sizeof(buf), numdb) != NULL) {
			privctx->numdbs = atoi(buf);
		}
		fclose(numdb);
	} else if (!readonly) {
		logthing(LOGTHING_ERROR, "Couldn't open num_keydb: %s",
				strerror(errno));
		numdb = fopen(buf, "w");
		if (numdb != NULL) {
			fprintf(numdb, "%d", privctx->numdbs);
			fclose(numdb);
		} else {
			logthing(LOGTHING_ERROR,
				"Couldn't write num_keydb: %s",
				strerror(errno));
		}
	}

	privctx->dbconns = calloc(privctx->numdbs, sizeof (DB *));
	if (privctx->dbconns == NULL) {
		logthing(LOGTHING_CRITICAL,
				"Couldn't allocate memory for dbconns");
		ret = 1;
	}

	if (ret == 0) {
		ret = db_env_create(&privctx->dbenv, 0);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL,
				"db_env_create: %s", db_strerror(ret));
		}
	}

	/*
	 * Up the number of locks we're allowed at once. We base this on
	 * the maximum number of keys we're going to return.
	 */
	maxlocks = config.maxkeys * 16;
	if (maxlocks < 1000) {
		maxlocks = 1000;
	}
	privctx->dbenv->set_lk_max_locks(privctx->dbenv, maxlocks);
	privctx->dbenv->set_lk_max_objects(privctx->dbenv, maxlocks);

	/*
	 * Enable deadlock detection so that we don't block indefinitely on
	 * anything. What we really want is simple 2 state locks, but I'm not
	 * sure how to make the standard DB functions do that yet.
	 */
	if (ret == 0) {
		privctx->dbenv->set_errcall(privctx->dbenv, &db4_errfunc);
		ret = privctx->dbenv->set_lk_detect(privctx->dbenv, DB_LOCK_DEFAULT);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL,
				"db_env_create: %s", db_strerror(ret));
		}
	}

	if (ret == 0) {
		ret = privctx->dbenv->open(privctx->dbenv, config.db_dir,
				DB_INIT_LOG | DB_INIT_MPOOL | DB_INIT_LOCK |
				DB_INIT_TXN |
				DB_CREATE,
				0);
#ifdef DB_VERSION_MISMATCH
		if (ret == DB_VERSION_MISMATCH) {
			privctx->dbenv->close(privctx->dbenv, 0);
			privctx->dbenv = NULL;
			ret = db4_upgradedb(privctx);
			if (ret == 0) {
				ret = db_env_create(&privctx->dbenv, 0);
			}
			if (ret == 0) {
				privctx->dbenv->set_errcall(privctx->dbenv,
					&db4_errfunc);
				privctx->dbenv->set_lk_detect(privctx->dbenv,
					DB_LOCK_DEFAULT);
				ret = privctx->dbenv->open(privctx->dbenv,
					config.db_dir,
					DB_INIT_LOG | DB_INIT_MPOOL |
					DB_INIT_LOCK | DB_INIT_TXN |
					DB_CREATE | DB_RECOVER,
					0);

				if (ret == 0) {
					privctx->dbenv->txn_checkpoint(
							privctx->dbenv,
							0,
							0,
							DB_FORCE);
				}
			}
		}
#endif
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL,
					"Error opening db environment: %s (%s)",
					config.db_dir,
					db_strerror(ret));
			if (privctx->dbenv != NULL) {
				privctx->dbenv->close(privctx->dbenv, 0);
				privctx->dbenv = NULL;
			}
		}
	}

	if (ret == 0) {
		db4_starttrans(dbctx);

		for (i = 0; !ret && i < privctx->numdbs; i++) {
			ret = db_create(&privctx->dbconns[i],
					privctx->dbenv, 0);
			if (ret != 0) {
				logthing(LOGTHING_CRITICAL,
					"db_create: %s", db_strerror(ret));
			}

			if (ret == 0) {
				snprintf(buf, 1023, "keydb.%d.db", i);
				flags = DB_CREATE;
				if (readonly) {
					flags = DB_RDONLY;
				}
				ret = privctx->dbconns[i]->open(
						privctx->dbconns[i],
						privctx->txn,
						buf,
						"keydb",
						DB_HASH,
						flags,
						0664);
				if (ret != 0) {
					logthing(LOGTHING_CRITICAL,
						"Error opening key database:"
						" %s (%s)",
						buf,
						db_strerror(ret));
				}
			}
		}
	}

	if (ret == 0) {
		ret = db_create(&privctx->worddb, privctx->dbenv, 0);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL, "db_create: %s",
					db_strerror(ret));
		}
	}

	if (ret == 0) {
		ret = privctx->worddb->set_flags(privctx->worddb, DB_DUP);
	}

	if (ret == 0) {
		ret = privctx->worddb->open(privctx->worddb, privctx->txn,
				"worddb", "worddb", DB_BTREE,
				flags,
				0664);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL,
					"Error opening word database: %s (%s)",
					"worddb",
					db_strerror(ret));
		}
	}

	if (ret == 0) {
		ret = db_create(&privctx->id32db, privctx->dbenv, 0);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL, "db_create: %s",
					db_strerror(ret));
		}
	}

	if (ret == 0) {
		ret = privctx->id32db->set_flags(privctx->id32db, DB_DUP);
	}

	if (ret == 0) {
		ret = privctx->id32db->open(privctx->id32db, privctx->txn,
				"id32db", "id32db", DB_HASH,
				flags,
				0664);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL,
					"Error opening id32 database: %s (%s)",
					"id32db",
					db_strerror(ret));
		}
	}

	if (ret == 0) {
		ret = db_create(&privctx->skshashdb, privctx->dbenv, 0);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL, "db_create: %s",
					db_strerror(ret));
		}
	}

	if (ret == 0) {
		ret = privctx->skshashdb->open(privctx->skshashdb, privctx->txn,
				"skshashdb",
				"skshashdb", DB_HASH,
				flags,
				0664);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL,
				"Error opening skshash database: %s (%s)",
				"skshashdb",
				db_strerror(ret));
		}
	}

	if (ret == 0) {
		ret = db_create(&privctx->subkeydb, privctx->dbenv, 0);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL, "db_create: %s",
					db_strerror(ret));
		}
	}

	if (ret == 0) {
		ret = privctx->subkeydb->open(privctx->subkeydb, privctx->txn,
				"subkeydb", "subkeydb",
				DB_HASH,
				flags,
				0664);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL,
				"Error opening subkey database: %s (%s)",
				"subkeydb",
				db_strerror(ret));
		}
	}

	if (privctx->txn != NULL) {
		db4_endtrans(dbctx);
	}

	if (ret != 0) {
		db4_cleanupdb(dbctx);
		logthing(LOGTHING_CRITICAL,
				"Error opening database; exiting");
		exit(EXIT_FAILURE);
	}

	dbctx->cleanupdb		= db4_cleanupdb;
	dbctx->starttrans		= db4_starttrans;
	dbctx->endtrans			= db4_endtrans;
	dbctx->fetch_key_id		= db4_fetch_key_id;
	dbctx->fetch_key_fp		= generic_fetch_key_fp;
	dbctx->fetch_key_text		= db4_fetch_key_text;
	dbctx->fetch_key_skshash	= db4_fetch_key_skshash;
	dbctx->store_key		= db4_store_key;
	dbctx->update_keys		= generic_update_keys;
	dbctx->delete_key		= db4_delete_key;
	dbctx->getkeysigs		= generic_getkeysigs;
	dbctx->cached_getkeysigs	= generic_cached_getkeysigs;
	dbctx->keyid2uid		= generic_keyid2uid;
	dbctx->getfullkeyid		= db4_getfullkeyid;
	dbctx->iterate_keys		= db4_iterate_keys;

	return dbctx;
}
