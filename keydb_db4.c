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

/**
 *	dbenv - our database environment.
 */
static DB_ENV *dbenv = NULL;

/**
 *	numdb - The number of database files we have.
 */
static int numdbs = 16;

/**
 *	dbconn - our connections to the key database files.
 */
static DB **dbconns = NULL;

/**
 *	worddb - our connection to the word database.
 */
static DB *worddb = NULL;

/**
 *	id32db - our connection to the 32bit ID database.
 */
static DB *id32db = NULL;

/**
 *	skshashdb - our connection to the SKS hash database.
 */
static DB *skshashdb = NULL;

/**
 *	txn - our current transaction id.
 */
static DB_TXN *txn = NULL;

DB *keydb(uint64_t keyid)
{
	uint64_t keytrun;

	keytrun = keyid >> 8;

	return(dbconns[keytrun % numdbs]);
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
static bool db4_starttrans(void)
{
	int ret;

	log_assert(dbenv != NULL);
	log_assert(txn == NULL);

	ret = dbenv->txn_begin(dbenv,
		NULL, /* No parent transaction */
		&txn,
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
static void db4_endtrans(void)
{
	int ret;

	log_assert(dbenv != NULL);
	log_assert(txn != NULL);

	ret = txn->commit(txn,
		0);
	if (ret != 0) {
		logthing(LOGTHING_CRITICAL,
				"Error ending transaction: %s",
				db_strerror(ret));
		exit(1);
	}
	txn = NULL;

	return;
}

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	This function should be called upon program exit to allow the DB to
 *	cleanup after itself.
 */
static void db4_cleanupdb(void)
{
	int i = 0;

	if (dbenv != NULL) {
		dbenv->txn_checkpoint(dbenv, 0, 0, 0);
		if (skshashdb != NULL) {
			skshashdb->close(skshashdb, 0);
			skshashdb = NULL;
		}
		if (id32db != NULL) {
			id32db->close(id32db, 0);
			id32db = NULL;
		}
		if (worddb != NULL) {
			worddb->close(worddb, 0);
			worddb = NULL;
		}
		for (i = 0; i < numdbs; i++) {
			if (dbconns[i] != NULL) {
				dbconns[i]->close(dbconns[i], 0);
				dbconns[i] = NULL;
			}
		}
		free(dbconns);
		dbconns = NULL;
		dbenv->close(dbenv, 0);
		dbenv = NULL;
	}
}

/**
 *	db4_upgradedb - Upgrade a DB4 database
 *
 *	Called if we discover we need to upgrade our DB4 database; ie if
 *	we're running with a newer version of db4 than the database was
 *	created with.
 */
static int db4_upgradedb(int numdb)
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
	ret = db_env_create(&dbenv, 0);
	dbenv->set_errcall(dbenv, &db4_errfunc);
	dbenv->remove(dbenv, config.db_dir, 0);
	dbenv = NULL;
	for (i = 0; i < numdb; i++) {
		ret = db_create(&curdb, NULL, 0);
		if (ret == 0) {
			snprintf(buf, sizeof(buf) - 1, "%s/keydb.%d.db",
				config.db_dir, i);
			logthing(LOGTHING_DEBUG, "Upgrading %s", buf);
			ret = curdb->upgrade(curdb, buf, 0);
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
		ret = curdb->upgrade(curdb, buf, 0);
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
		ret = curdb->upgrade(curdb, buf, 0);
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
		ret = curdb->upgrade(curdb, buf, 0);
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
 *	initdb - Initialize the key database.
 *
 *	This function should be called before any of the other functions in
 *	this file are called in order to allow the DB to be initialized ready
 *	for access.
 */
static void db4_initdb(bool readonly)
{
	char       buf[1024];
	FILE      *numdb = NULL;
	int        ret = 0;
	int        i = 0;
	uint32_t   flags = 0;
	struct stat statbuf;
	int        maxlocks;

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
			numdbs = atoi(buf);
		}
		fclose(numdb);
	} else if (!readonly) {
		logthing(LOGTHING_ERROR, "Couldn't open num_keydb: %s",
				strerror(errno));
		numdb = fopen(buf, "w");
		if (numdb != NULL) {
			fprintf(numdb, "%d", numdbs);
			fclose(numdb);
		} else {
			logthing(LOGTHING_ERROR,
				"Couldn't write num_keydb: %s",
				strerror(errno));
		}
	}

	dbconns = calloc(numdbs, sizeof (DB *));
	if (dbconns == NULL) {
		logthing(LOGTHING_CRITICAL,
				"Couldn't allocate memory for dbconns");
		ret = 1;
	}

	if (ret == 0) {
		ret = db_env_create(&dbenv, 0);
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
	dbenv->set_lk_max_locks(dbenv, maxlocks);
	dbenv->set_lk_max_objects(dbenv, maxlocks);

	/*
	 * Enable deadlock detection so that we don't block indefinitely on
	 * anything. What we really want is simple 2 state locks, but I'm not
	 * sure how to make the standard DB functions do that yet.
	 */
	if (ret == 0) {
		dbenv->set_errcall(dbenv, &db4_errfunc);
		ret = dbenv->set_lk_detect(dbenv, DB_LOCK_DEFAULT);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL,
				"db_env_create: %s", db_strerror(ret));
		}
	}

	if (ret == 0) {
		ret = dbenv->open(dbenv, config.db_dir,
				DB_INIT_LOG | DB_INIT_MPOOL | DB_INIT_LOCK |
				DB_INIT_TXN |
				DB_CREATE,
				0);
#ifdef DB_VERSION_MISMATCH
		if (ret == DB_VERSION_MISMATCH) {
			dbenv->close(dbenv, 0);
			dbenv = NULL;
			ret = db4_upgradedb(numdbs);
			if (ret == 0) {
				ret = db_env_create(&dbenv, 0);
			}
			if (ret == 0) {
				dbenv->set_errcall(dbenv, &db4_errfunc);
				dbenv->set_lk_detect(dbenv, DB_LOCK_DEFAULT);
				ret = dbenv->open(dbenv, config.db_dir,
					DB_INIT_LOG | DB_INIT_MPOOL |
					DB_INIT_LOCK | DB_INIT_TXN |
					DB_CREATE | DB_RECOVER,
					0);

				if (ret == 0) {
					dbenv->txn_checkpoint(dbenv,
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
			dbenv->close(dbenv, 0);
			dbenv = NULL;
		}
	}

	if (ret == 0) {
		db4_starttrans();

		for (i = 0; !ret && i < numdbs; i++) {
			ret = db_create(&dbconns[i], dbenv, 0);
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
				ret = dbconns[i]->open(dbconns[i],
						txn,
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
		ret = db_create(&worddb, dbenv, 0);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL, "db_create: %s",
					db_strerror(ret));
		}
	}

	if (ret == 0) {
		ret = worddb->set_flags(worddb, DB_DUP);
	}

	if (ret == 0) {
		ret = worddb->open(worddb, txn, "worddb", "worddb", DB_BTREE,
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
		ret = db_create(&id32db, dbenv, 0);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL, "db_create: %s",
					db_strerror(ret));
		}
	}

	if (ret == 0) {
		ret = id32db->set_flags(id32db, DB_DUP);
	}

	if (ret == 0) {
		ret = id32db->open(id32db, txn, "id32db", "id32db", DB_HASH,
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
		ret = db_create(&skshashdb, dbenv, 0);
		if (ret != 0) {
			logthing(LOGTHING_CRITICAL, "db_create: %s",
					db_strerror(ret));
		}
	}

	if (ret == 0) {
		ret = skshashdb->open(skshashdb, txn, "skshashdb",
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

	if (txn != NULL) {
		db4_endtrans();
	}

	if (ret != 0) {
		db4_cleanupdb();
		logthing(LOGTHING_CRITICAL,
				"Error opening database; exiting");
		exit(EXIT_FAILURE);
	}
	
	return;
}

/**
 *	getfullkeyid - Maps a 32bit key id to a 64bit one.
 *	@keyid: The 32bit keyid.
 *
 *	This function maps a 32bit key id to the full 64bit one. It returns the
 *	full keyid. If the key isn't found a keyid of 0 is returned.
 */
static uint64_t db4_getfullkeyid(uint64_t keyid)
{
	DBT       key, data;
	DBC      *cursor = NULL;
	uint32_t  shortkeyid = 0;
	int       ret = 0;

	if (keyid < 0x100000000LL) {
		ret = id32db->cursor(id32db,
				txn,
				&cursor,
				0);   /* flags */

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

		ret = cursor->c_close(cursor);
		cursor = NULL;
	}
	
	return keyid;
}

/**
 *	fetch_key - Given a keyid fetch the key from storage.
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
static int db4_fetch_key(uint64_t keyid, struct openpgp_publickey **publickey,
		bool intrans)
{
	struct openpgp_packet_list *packets = NULL;
	DBT key, data;
	int ret = 0;
	int numkeys = 0;
	struct buffer_ctx fetchbuf;

	if (keyid < 0x100000000LL) {
		keyid = db4_getfullkeyid(keyid);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	data.size = 0;
	data.data = NULL;

	key.size = sizeof(keyid);
	key.data = &keyid;

	if (!intrans) {
		db4_starttrans();
	}

	ret = keydb(keyid)->get(keydb(keyid),
			txn,
			&key,
			&data,
			0); /* flags*/
	
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
		db4_endtrans();
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
static int db4_fetch_key_text(const char *search,
		struct openpgp_publickey **publickey)
{
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
		db4_starttrans();

		ret = worddb->cursor(worddb,
				txn,
				&cursor,
				0);   /* flags */

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
		ret = cursor->c_close(cursor);
		cursor = NULL;
		firstpass = 0;
		db4_endtrans();
	}
	llfree(wordlist, NULL);
	wordlist = NULL;

	if (keylist.count > config.maxkeys) {
		keylist.count = config.maxkeys;
	}
	
	db4_starttrans();
	for (i = 0; i < keylist.count; i++) {
		numkeys += db4_fetch_key(keylist.keys[i],
			publickey,
			true);
	}
	array_free(&keylist);
	free(searchtext);
	searchtext = NULL;

	db4_endtrans();
	
	return (numkeys);
}

static int db4_fetch_key_skshash(const struct skshash *hash,
		struct openpgp_publickey **publickey)
{
	DBT       key, data;
	DBC      *cursor = NULL;
	uint64_t  keyid = 0;
	int       ret = 0;

	ret = skshashdb->cursor(skshashdb,
			txn,
			&cursor,
			0);   /* flags */

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

	ret = cursor->c_close(cursor);
	cursor = NULL;

	return db4_fetch_key(keyid, publickey, false);
}

/**
 *	delete_key - Given a keyid delete the key from storage.
 *	@keyid: The keyid to delete.
 *	@intrans: If we're already in a transaction.
 *
 *	This function deletes a public key from whatever storage mechanism we
 *	are using. Returns 0 if the key existed.
 */
static int db4_delete_key(uint64_t keyid, bool intrans)
{
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
		db4_starttrans();
	}

	db4_fetch_key(keyid, &publickey, true);

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
				
		ret = worddb->cursor(worddb,
			txn,
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
		ret = cursor->c_close(cursor);
		cursor = NULL;

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
		ret = id32db->cursor(id32db,
			txn,
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
		ret = cursor->c_close(cursor);
		cursor = NULL;

	}

	if (!deadlock) {
		ret = skshashdb->cursor(skshashdb,
			txn,
			&cursor,
			0);   /* flags */
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

		ret = cursor->c_close(cursor);
		cursor = NULL;
	}

	if (!deadlock) {
		key.data = &keyid;
		key.size = sizeof(keyid);

		keydb(keyid)->del(keydb(keyid),
				txn,
				&key,
				0); /* flags */
	}

	if (!intrans) {
		db4_endtrans();
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
static int db4_store_key(struct openpgp_publickey *publickey, bool intrans,
		bool update)
{
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

	keyid = get_keyid(publickey);

	if (!intrans) {
		db4_starttrans();
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
		deadlock = (db4_delete_key(keyid, true) == -1);
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

		ret = keydb(keyid)->put(keydb(keyid),
				txn,
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
			ret = worddb->put(worddb,
				txn,
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

		ret = id32db->put(id32db,
			txn,
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
			shortkeyid = subkeyids[i++] & 0xFFFFFFFF;

			memset(&key, 0, sizeof(key));
			memset(&data, 0, sizeof(data));
			key.data = &shortkeyid;
			key.size = sizeof(shortkeyid);
			data.data = &keyid;
			data.size = sizeof(keyid);

			ret = id32db->put(id32db,
				txn,
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

		ret = skshashdb->put(skshashdb,
			txn,
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
		db4_endtrans();
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
static int db4_iterate_keys(void (*iterfunc)(void *ctx,
		struct openpgp_publickey *key),	void *ctx)
{
	DBT                         dbkey, data;
	DBC                        *cursor = NULL;
	int                         ret = 0;
	int                         i = 0;
	int                         numkeys = 0;
	struct buffer_ctx           fetchbuf;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_publickey   *key = NULL;

	for (i = 0; i < numdbs; i++) {
		ret = dbconns[i]->cursor(dbconns[i],
			NULL,
			&cursor,
			0);   /* flags */

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

		ret = cursor->c_close(cursor);
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
#include "keydb.c"

struct dbfuncs keydb_db4_funcs = {
	.initdb			= db4_initdb,
	.cleanupdb		= db4_cleanupdb,
	.starttrans		= db4_starttrans,
	.endtrans		= db4_endtrans,
	.fetch_key		= db4_fetch_key,
	.fetch_key_text		= db4_fetch_key_text,
	.fetch_key_skshash	= db4_fetch_key_skshash,
	.store_key		= db4_store_key,
	.update_keys		= generic_update_keys,
	.delete_key		= db4_delete_key,
	.getkeysigs		= generic_getkeysigs,
	.cached_getkeysigs	= generic_cached_getkeysigs,
	.keyid2uid		= generic_keyid2uid,
	.getfullkeyid		= db4_getfullkeyid,
	.iterate_keys		= db4_iterate_keys,
};
