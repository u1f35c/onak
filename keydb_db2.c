/*
 * keydb_db2.c - Routines to store and fetch keys in a DB2 file (a la pksd)
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <db2/db.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "keydb.h"
#include "keyid.h"
#include "keyindex.h"
#include "keystructs.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"

#define KEYDB_KEYID_BYTES 4

/**
 *	db2_numdb - The number of database files we have.
 */
static int db2_numdb = 16;

/**
 *	db2_keydbfiles - An array of DB structs for our key database files.
 */
static DB **db2_keydbfiles = NULL;

/**
 *	db2_env - Database environment variable.
 */
static DB_ENV db2_env;

/*
 * Shared with CGI buffer stuff...
 */
struct db2_get_ctx {
	char *buffer;
	int offset;
	int size;
};

/**
 *	keydb_fetchchar - Fetches a char from a buffer.
 */
int keydb_fetchchar(void *ctx, int count, unsigned char *c)
{
	struct db2_get_ctx *buf = NULL;
	int i;
	
	buf = (struct db2_get_ctx *) ctx;
	for (i = 0; i < count; i++) {
		c[i] = buf->buffer[buf->offset++];
	}

	return (((buf->offset) == (buf->size)) ? 1 : 0);
}

/**
 *	keydb_putchar - Puts a char to a file.
 */
static int keydb_putchar(void *fd, unsigned char c)
{
//	return !(lo_write(dbconn, *(int *) fd, &c, sizeof(c)));
	return 1;
}

DB *keydb(DBT *key)
{
	/*
	 * keyid's are 8 bytes, msb first.  so start from the end.  use 16
	 * bits, since that's enough to divide by any small number of db files.
	 */
	unsigned char *keydata = (unsigned char *) key->data;
	unsigned long keyidnum;

	keyidnum = (keydata[KEYDB_KEYID_BYTES-2]<<8)|keydata[KEYDB_KEYID_BYTES-1];
	return(db2_keydbfiles[keyidnum % db2_numdb]);
}

/**
 *	initdb - Initialize the key database.
 *
 *	This function should be called before any of the other functions in
 *	this file are called in order to allow the DB to be initialized ready
 *	for access.
 */
void initdb(void)
{
	DB_INFO keydbinfo;
	int i;
	int ret;
	char keydbname[20];

	memset(&db2_env, 0, sizeof(db2_env));

	/*
	 * Tunable param. Just using what pksd does for the moment. Bigger uses
	 * more memory but improves performance. Bigger than physical memory
	 * makes no sense.
	 */
	db2_env.mp_size = 20 * 1024 * 1024;

	ret = db_appinit(config.db2_dbpath, NULL,
			&db2_env, DB_INIT_MPOOL|DB_INIT_LOCK);
	if (!ret) {
		db2_keydbfiles = (DB **) malloc(sizeof (DB *) * db2_numdb);
		memset(&keydbinfo, 0, sizeof(keydbinfo));
		keydbinfo.db_pagesize = 8192;
		for (i = 0; i < db2_numdb; i++) {
			db2_keydbfiles[i] = NULL;
			snprintf(keydbname, 19, "keydb%03d", i);
			ret = db_open(keydbname, DB_HASH, DB_RDONLY, 0644,
					&db2_env, &keydbinfo,
					&db2_keydbfiles[i]);
			if (ret) {
				fprintf(stderr, "Error opening db file %d (errno %d)\n",
					i, ret);
				exit(1);
			}
		}
	} else {
		fprintf(stderr, "Error initializing db (%d).\n", ret);
		exit(1);
	}
}

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	This function should be called upon program exit to allow the DB to
 *	cleanup after itself.
 */
void cleanupdb(void)
{
	int i;

	for (i = 0; i < db2_numdb; i++) {
		if (db2_keydbfiles[i] != NULL) {
			(*(db2_keydbfiles[i]->close))(db2_keydbfiles[i], 0);
			db2_keydbfiles[i] = NULL;
		}
	}

	db_appexit(&db2_env);
}

/**
 *	starttrans - Start a transaction.
 *
 *	Start a transaction. Intended to be used if we're about to perform many
 *	operations on the database to help speed it all up, or if we want
 *	something to only succeed if all relevant operations are successful.
 */
bool starttrans(void)
{
	return true;
}

/**
 *	endtrans - End a transaction.
 *
 *	Ends a transaction.
 */
void endtrans(void)
{
	return;
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
int fetch_key(uint64_t keyid, struct openpgp_publickey **publickey,
		bool intrans)
{
	struct openpgp_packet_list *packets = NULL;
	int ret;
	DBT key, data;
	char id[KEYDB_KEYID_BYTES];
	struct db2_get_ctx fetchbuf;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	id[0] = (keyid >> 24) & 0xFF;
	id[1] = (keyid >> 16) & 0xFF;
	id[2] = (keyid >> 8) & 0xFF;
	id[3] = keyid & 0xFF;

	key.data = id;
	key.size = KEYDB_KEYID_BYTES;

	ret = (*(keydb(&key)->get))(keydb(&key), NULL, &key, &data, 0);
	if (ret == 0) {
		fetchbuf.buffer = data.data;
		fetchbuf.offset = 0;
		fetchbuf.size = data.size;
		read_openpgp_stream(keydb_fetchchar, &fetchbuf, &packets);
		parse_keys(packets, publickey);
	}

	return (!ret);
}

/**
 *	fetch_key_text - Trys to find the keys that contain the supplied text.
 *	@search: The text to search for.
 *	@publickey: A pointer to a structure to return the key in.
 *
 *	This function searches for the supplied text and returns the keys that
 *	contain it.
 */
int fetch_key_text(const char *search, struct openpgp_publickey **publickey)
{
	return 0;
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
 *	the file.
 */
int store_key(struct openpgp_publickey *publickey, bool intrans, bool update)
{
	return 0;
}

/**
 *	delete_key - Given a keyid delete the key from storage.
 *	@keyid: The keyid to delete.
 *	@intrans: If we're already in a transaction.
 *
 *	This function deletes a public key from whatever storage mechanism we
 *	are using. Returns 0 if the key existed.
 */
int delete_key(uint64_t keyid, bool intrans)
{
	return (1);
}

/*
 * Include the basic keydb routines.
 */
#define NEED_KEYID2UID 1
#define NEED_GETKEYSIGS 1
#define NEED_GETFULLKEYID 1
#include "keydb.c"
