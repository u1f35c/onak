/*
 * keydb_db3.c - Routines to store and fetch keys in a DB3 database.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#include <sys/types.h>
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
#include "keydb.h"
#include "keyid.h"
#include "keyindex.h"
#include "keystructs.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"

/**
 *	dbconn - our connection to the key database.
 */
static DB *dbconn = NULL;

/**
 *	worddb - our connection to the word database.
 */
static DB *worddb = NULL;

/**
 *	makewordlist - Takes a string and splits it into a set of unique words.
 *	@wordlist: The current word list.
 *	@words: The string to split and add.
 *
 *	We take words and split it on non alpha numeric characters. These get
 *	added to the word list if they're not already present. If the wordlist
 *	is NULL then we start a new list, otherwise it's search for already
 *	added words. Note that words is modified in the process of scanning.
 *
 *	Returns the new word list.
 */
struct ll *makewordlist(struct ll *wordlist, char *word)
{
	char *start = NULL;
	char *end = NULL;

	/*
	 * Walk through the words string, spliting on non alphanumerics and
	 * then checking if the word already exists in the list. If not then
	 * we add it.
	 */
	end = word;
	while (end != NULL && *end != 0) {
		start = end;
		while (*start != 0 && !isalnum(*start)) {
			start++;
		}
		end = start;
		while (*end != 0 && isalnum(*end)) {
			*end = tolower(*end);
			end++;
		}
		if (end - start > 1) {
			if (*end != 0) {
				*end = 0;
				end++;
			}
			
			if (llfind(wordlist, start,
					strcmp) == NULL) {
				wordlist = lladd(wordlist,
						start);
			}
		}
	}

	return wordlist;
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
	char buf[1024];
	int ret = 0;

	strcpy(buf, config.db_dir);
	strcat(buf, "/keydb.db");
	
	ret = db_create(&dbconn, NULL, 0);
	if (ret != 0) {
		fprintf(stderr, "db_create: %s\n", db_strerror(ret));
		exit(1);
	}

	ret = dbconn->open(dbconn, buf, NULL, DB_HASH,
			DB_CREATE,
			0664);
	if (ret != 0) {
		dbconn->err(dbconn, ret, "%s", buf);
		exit(1);
	}

	strcpy(buf, config.db_dir);
	strcat(buf, "/worddb");
	
	ret = db_create(&worddb, NULL, 0);
	if (ret != 0) {
		fprintf(stderr, "db_create: %s\n", db_strerror(ret));
		exit(1);
	}
	ret = worddb->set_flags(worddb, DB_DUP);

	ret = worddb->open(worddb, buf, NULL, DB_BTREE,
			DB_CREATE,
			0664);
	if (ret != 0) {
		worddb->err(worddb, ret, "%s", buf);
		exit(1);
	}
	
	return;
}

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	This function should be called upon program exit to allow the DB to
 *	cleanup after itself.
 */
void cleanupdb(void)
{
	worddb->close(worddb, 0);
	worddb = NULL;
	dbconn->close(dbconn, 0);
	dbconn = NULL;
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
	DBT key, data;
	int ret = 0;
	int numkeys = 0;
	struct buffer_ctx fetchbuf;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	data.size = 0;
	data.data = NULL;

	key.size = sizeof(keyid);
	key.data = &keyid;
	keyid &= 0xFFFFFFFF;

	ret = dbconn->get(dbconn,
			NULL, /* txn id */
			&key,
			&data,
			0); /* flags*/
	
	if (ret == 0) {
		fetchbuf.buffer = data.data;
		fetchbuf.offset = 0;
		fetchbuf.size = data.size;
		read_openpgp_stream(buffer_fetchchar, &fetchbuf,
				&packets);
		parse_keys(packets, publickey);
		free_packet_list(packets);
		packets = NULL;
		numkeys++;
	} else if (ret != DB_NOTFOUND) {
		dbconn->err(dbconn, ret, "Problem retrieving key");
	}

	return (numkeys);
}

int worddb_cmp(const char *d1, const char *d2)
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
int fetch_key_text(const char *search, struct openpgp_publickey **publickey)
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
	struct ll *keylist = NULL;
	struct ll *newkeylist = NULL;

	numkeys = 0;
	searchtext = strdup(search);
	wordlist = makewordlist(wordlist, searchtext);


	ret = worddb->cursor(worddb,
			NULL, /* txn */
			&cursor,
			0);   /* flags */

	for (curword = wordlist; curword != NULL; curword = curword->next) {
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

			if (keylist == NULL ||
					llfind(keylist, data.data,
						worddb_cmp) != NULL) {
				newkeylist = lladd(newkeylist, data.data);
				data.data = NULL;
			} else {
				free(data.data);
				data.data = NULL;
			}
			ret = cursor->c_get(cursor,
					&key,
					&data,
					DB_NEXT);
		}
		llfree(keylist, free);
		keylist = newkeylist;
		newkeylist = NULL;
		if (data.data != NULL) {
			free(data.data);
			data.data = NULL;
		}
	}
	llfree(wordlist, NULL);
	wordlist = NULL;
	
	for (newkeylist = keylist;
			newkeylist != NULL && numkeys < config.maxkeys;
			newkeylist = newkeylist->next) {

			keyid = 0;
			for (i = 4; i < 12; i++) {
				keyid <<= 8;
				keyid += ((unsigned char *)
						newkeylist->object)[i];
			}

			numkeys += fetch_key(keyid,
					publickey,
					false);
	}
	llfree(keylist, free);
	keylist = NULL;
	free(searchtext);
	searchtext = NULL;

	ret = cursor->c_close(cursor);
	cursor = NULL;
	
	return (numkeys);
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
int store_key(struct openpgp_publickey *publickey, bool intrans, bool update)
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
	char     **uids = NULL;
	char      *primary = NULL;
	unsigned char worddb_data[12];
	struct ll *wordlist = NULL;
	struct ll *curword  = NULL;

	keyid = get_keyid(publickey);

	/*
	 * Delete the key if we already have it.
	 *
	 * TODO: Can we optimize this perhaps? Possibly when other data is
	 * involved as well? I suspect this is easiest and doesn't make a lot
	 * of difference though - the largest chunk of data is the keydata and
	 * it definitely needs updated.
	 */
	if (update) {
		delete_key(keyid, true);
	}

	/*
	 * Convert the key to a flat set of binary data.
	 */
	next = publickey->next;
	publickey->next = NULL;
	flatten_publickey(publickey, &packets, &list_end);
	publickey->next = next;

	storebuf.offset = 0; 
	storebuf.size = 8192;
	storebuf.buffer = malloc(8192);
	
	write_openpgp_stream(buffer_putchar, &storebuf, packets);

	/*
	 * Now we have the key data store it in the DB; the keyid is the key.
	 */
	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	key.data = &keyid;
	key.size = sizeof(keyid);
	keyid &= 0xFFFFFFFF;
	data.size = storebuf.offset;
	data.data = storebuf.buffer;

	ret = dbconn->put(dbconn,
			NULL, /* txn id */
			&key,
			&data,
			0); /* flags*/
	if (ret != 0) {
		dbconn->err(dbconn, ret, "Problem storing key");
	}

	free(storebuf.buffer);
	storebuf.buffer = NULL;
	storebuf.size = 0;
	storebuf.offset = 0; 

	free_packet_list(packets);
	packets = NULL;

	/*
	 * Walk through our uids storing the words into the db with the keyid.
	 */
	uids = keyuids(publickey, &primary);
	if (uids != NULL) {
		for (i = 0; ret == 0 && uids[i] != NULL; i++) {
			wordlist = makewordlist(wordlist, uids[i]);
		}

		for (curword = wordlist; curword != NULL;
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
				0,
				&key,
				&data,
				0);
			if (ret != 0) {
				worddb->err(worddb, ret,
					"Problem storing key");
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
	struct openpgp_publickey *publickey = NULL;
	DBT key, data;
	DBC *cursor = NULL;
	int ret = 0;
	int i;
	char **uids = NULL;
	char *primary = NULL;
	unsigned char worddb_data[12];
	struct ll *wordlist = NULL;
	struct ll *curword  = NULL;

	keyid &= 0xFFFFFFFF;

	fetch_key(keyid, &publickey, intrans);

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
			NULL, /* txn */
			&cursor,
			0);   /* flags */

		for (curword = wordlist; curword != NULL;
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
				worddb->err(worddb, ret,
					"Problem deleting word.");
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

	key.data = &keyid;
	key.size = sizeof(keyid);

	dbconn->del(dbconn,
			NULL, /* txn id */
			&key,
			0); /* flags */

	return (ret == DB_NOTFOUND);
}

/*
 * Include the basic keydb routines.
 */
#define NEED_GETFULLKEYID 1
#define NEED_GETKEYSIGS 1
#define NEED_KEYID2UID 1
#include "keydb.c"
