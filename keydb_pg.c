/*
 * keydb_pg.c - Routines to store and fetch keys in a PostGres database.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 *
 * $Id: keydb_pg.c,v 1.14 2004/03/23 12:33:47 noodles Exp $
 */

#include <postgresql/libpq-fe.h>
#include <postgresql/libpq/libpq-fs.h>

//#include <libpq-fe.h>
//#include <libpq/libpq-fs.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hash.h"
#include "keydb.h"
#include "keyid.h"
#include "decodekey.h"
#include "keystructs.h"
#include "log.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"

/**
 *	dbconn - our connection to the database.
 */
static PGconn *dbconn = NULL;

/**
 *	keydb_fetchchar - Fetches a char from a file.
 */
static int keydb_fetchchar(void *fd, size_t count, unsigned char *c)
{
	return (!lo_read(dbconn, *(int *) fd, c, count));
}

/**
 *	keydb_putchar - Puts a char to a file.
 */
static int keydb_putchar(void *fd, size_t count, unsigned char *c)
{
	return !(lo_write(dbconn, *(int *) fd, c, count));
}

/**
 *	initdb - Initialize the key database.
 *
 *	This function should be called before any of the other functions in
 *	this file are called in order to allow the DB to be initialized ready
 *	for access.
 */
void initdb(bool readonly)
{
	dbconn = PQsetdbLogin(config.pg_dbhost, // host
			NULL, // port
			NULL, // options
			NULL, // tty
			config.pg_dbname, // database
			config.pg_dbuser,  //login
			config.pg_dbpass); // password

	if (PQstatus(dbconn) == CONNECTION_BAD) {
		logthing(LOGTHING_CRITICAL, "Connection to database failed.");
		logthing(LOGTHING_CRITICAL, "%s", PQerrorMessage(dbconn));
		PQfinish(dbconn);
		dbconn = NULL;
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
	PQfinish(dbconn);
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
	PGresult *result = NULL;
	
	result = PQexec(dbconn, "BEGIN");
	PQclear(result);

	return true;
}

/**
 *	endtrans - End a transaction.
 *
 *	Ends a transaction.
 */
void endtrans(void)
{
	PGresult *result = NULL;

	result = PQexec(dbconn, "COMMIT");
	PQclear(result);

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
	PGresult *result = NULL;
	char *oids = NULL;
	char statement[1024];
	int fd = -1;
	int i = 0;
	int numkeys = 0;
	Oid key_oid;

	if (!intrans) {
		result = PQexec(dbconn, "BEGIN");
		PQclear(result);
	}
	
	if (keyid > 0xFFFFFFFF) {
		snprintf(statement, 1023,
			"SELECT keydata FROM onak_keys WHERE keyid = '%llX'",
			keyid);
	} else {
		snprintf(statement, 1023,
			"SELECT keydata FROM onak_keys WHERE keyid "
			"LIKE '%%%llX'",
			keyid);
	}
	result = PQexec(dbconn, statement);

	if (PQresultStatus(result) == PGRES_TUPLES_OK) {
		numkeys = PQntuples(result);
		for (i = 0; i < numkeys && numkeys <= config.maxkeys; i++) {
			oids = PQgetvalue(result, i, 0);
			key_oid = (Oid) atoi(oids);

			fd = lo_open(dbconn, key_oid, INV_READ);
			if (fd < 0) {
				logthing(LOGTHING_ERROR,
						"Can't open large object.");
			} else {
				read_openpgp_stream(keydb_fetchchar, &fd,
						&packets, 0);
				parse_keys(packets, publickey);
				lo_close(dbconn, fd);
				free_packet_list(packets);
				packets = NULL;
			}
		}
	} else if (PQresultStatus(result) != PGRES_TUPLES_OK) {
		logthing(LOGTHING_ERROR, "Problem retrieving key from DB.");
	}

	PQclear(result);

	if (!intrans) {
		result = PQexec(dbconn, "COMMIT");
		PQclear(result);
	}
	return (numkeys);
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
	struct openpgp_packet_list *packets = NULL;
	PGresult *result = NULL;
	char *oids = NULL;
	char statement[1024];
	int fd = -1;
	int i = 0;
	int numkeys = 0;
	Oid key_oid;
	char *newsearch = NULL;

	result = PQexec(dbconn, "BEGIN");
	PQclear(result);

	newsearch = malloc(strlen(search) * 2 + 1);
	memset(newsearch, 0, strlen(search) * 2 + 1);
	PQescapeString(newsearch, search, strlen(search));
	snprintf(statement, 1023,
			"SELECT DISTINCT onak_keys.keydata FROM onak_keys, "
			"onak_uids WHERE onak_keys.keyid = onak_uids.keyid "
			"AND onak_uids.uid LIKE '%%%s%%'",
			newsearch);
	result = PQexec(dbconn, statement);
	free(newsearch);
	newsearch = NULL;

	if (PQresultStatus(result) == PGRES_TUPLES_OK) {
		numkeys = PQntuples(result);
		for (i = 0; i < numkeys && numkeys <= config.maxkeys; i++) {
			oids = PQgetvalue(result, i, 0);
			key_oid = (Oid) atoi(oids);

			fd = lo_open(dbconn, key_oid, INV_READ);
			if (fd < 0) {
				logthing(LOGTHING_ERROR,
						"Can't open large object.");
			} else {
				read_openpgp_stream(keydb_fetchchar, &fd,
						&packets);
				parse_keys(packets, publickey);
				lo_close(dbconn, fd);
				free_packet_list(packets);
				packets = NULL;
			}
		}
	} else if (PQresultStatus(result) != PGRES_TUPLES_OK) {
		logthing(LOGTHING_ERROR, "Problem retrieving key from DB.");
	}

	PQclear(result);

	result = PQexec(dbconn, "COMMIT");
	PQclear(result);
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
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct openpgp_publickey *next = NULL;
	struct openpgp_signedpacket_list *curuid = NULL;
	PGresult *result = NULL;
	char statement[1024];
	Oid key_oid;
	int fd;
	char **uids = NULL;
	char *primary = NULL;
	char *safeuid = NULL;
	int i;

	if (!intrans) {
		result = PQexec(dbconn, "BEGIN");
		PQclear(result);
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
		delete_key(get_keyid(publickey), true);
	}

	next = publickey->next;
	publickey->next = NULL;
	flatten_publickey(publickey, &packets, &list_end);
	publickey->next = next;
		
	key_oid = lo_creat(dbconn, INV_READ | INV_WRITE);
	if (key_oid == 0) {
		logthing(LOGTHING_ERROR, "Can't create key OID");
	} else {
		fd = lo_open(dbconn, key_oid, INV_WRITE);
		write_openpgp_stream(keydb_putchar, &fd, packets);
		lo_close(dbconn, fd);
	}
	free_packet_list(packets);
	packets = NULL;

	snprintf(statement, 1023, 
			"INSERT INTO onak_keys (keyid, keydata) VALUES "
			"('%llX', '%d')", 
			get_keyid(publickey),
			key_oid);
	result = PQexec(dbconn, statement);

	if (PQresultStatus(result) != PGRES_COMMAND_OK) {
		logthing(LOGTHING_ERROR, "Problem storing key in DB.");
		logthing(LOGTHING_ERROR, "%s", PQresultErrorMessage(result));
	}
	PQclear(result);

	uids = keyuids(publickey, &primary);
	if (uids != NULL) {
		for (i = 0; uids[i] != NULL; i++) {
			safeuid = malloc(strlen(uids[i]) * 2 + 1);
			if (safeuid != NULL) {
				memset(safeuid, 0, strlen(uids[i]) * 2 + 1);
				PQescapeString(safeuid, uids[i],
						strlen(uids[i]));

				snprintf(statement, 1023,
					"INSERT INTO onak_uids "
					"(keyid, uid, pri) "
					"VALUES	('%llX', '%s', '%c')",
					get_keyid(publickey),
					safeuid,
					(uids[i] == primary) ? 't' : 'f');
				result = PQexec(dbconn, statement);

				free(safeuid);
				safeuid = NULL;
			}
			if (uids[i] != NULL) {
				free(uids[i]);
				uids[i] = NULL;
			}

			if (PQresultStatus(result) != PGRES_COMMAND_OK) {
				logthing(LOGTHING_ERROR,
						"Problem storing key in DB.");
				logthing(LOGTHING_ERROR, "%s",
						PQresultErrorMessage(result));
			}
			/*
			 * TODO: Check result.
			 */
			PQclear(result);
		}
		free(uids);
		uids = NULL;
	}

	for (curuid = publickey->uids; curuid != NULL; curuid = curuid->next) {
		for (packets = curuid->sigs; packets != NULL; 
				packets = packets->next) {
			snprintf(statement, 1023,
				"INSERT INTO onak_sigs (signer, signee) "
				"VALUES	('%llX', '%llX')",
				sig_keyid(packets->packet),
				get_keyid(publickey));
			result = PQexec(dbconn, statement);
			PQclear(result);
		}
	}

	if (!intrans) {
		result = PQexec(dbconn, "COMMIT");
		PQclear(result);
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
	PGresult *result = NULL;
	char *oids = NULL;
	char statement[1024];
	int found = 1;
	int i;
	Oid key_oid;

	if (!intrans) {
		result = PQexec(dbconn, "BEGIN");
		PQclear(result);
	}
	
	snprintf(statement, 1023,
			"SELECT keydata FROM onak_keys WHERE keyid = '%llX'",
			keyid);
	result = PQexec(dbconn, statement);

	if (PQresultStatus(result) == PGRES_TUPLES_OK) {
		found = 0;
		i = PQntuples(result);
		while (i > 0) {
			oids = PQgetvalue(result, i-1, 0);
			key_oid = (Oid) atoi(oids);
			lo_unlink(dbconn, key_oid);
			i--;
		}
		PQclear(result);

		snprintf(statement, 1023,
			"DELETE FROM onak_keys WHERE keyid = '%llX'",
			keyid);
		result = PQexec(dbconn, statement);
		PQclear(result);

		snprintf(statement, 1023,
			"DELETE FROM onak_sigs WHERE signee = '%llX'",
			keyid);
		result = PQexec(dbconn, statement);
		PQclear(result);

		snprintf(statement, 1023,
			"DELETE FROM onak_uids WHERE keyid = '%llX'",
			keyid);
		result = PQexec(dbconn, statement);
	} else if (PQresultStatus(result) != PGRES_TUPLES_OK) {
		logthing(LOGTHING_ERROR,
				"Problem retrieving key (%llX) from DB.",
				keyid);
	}

	PQclear(result);

	if (!intrans) {
		result = PQexec(dbconn, "COMMIT");
		PQclear(result);
	}
	return (found);
}

/**
 *	keyid2uid - Takes a keyid and returns the primary UID for it.
 *	@keyid: The keyid to lookup.
 */
char *keyid2uid(uint64_t keyid)
{
	PGresult *result = NULL;
	char statement[1024];
	char *uid = NULL;

	snprintf(statement, 1023,
		"SELECT uid FROM onak_uids WHERE keyid = '%llX' AND pri = 't'",
		keyid);
	result = PQexec(dbconn, statement);

	/*
	 * Technically we only expect one response to the query; a key only has
	 * one primary ID. Better to return something than nothing though.
	 *
	 * TODO: Log if we get more than one response? Needs logging framework
	 * first though.
	 */
	if (PQresultStatus(result) == PGRES_TUPLES_OK &&
			PQntuples(result) >= 1) {
		uid = strdup(PQgetvalue(result, 0, 0));
	} else if (PQresultStatus(result) != PGRES_TUPLES_OK) {
		logthing(LOGTHING_ERROR,
				"Problem retrieving key (%llX) from DB.",
				keyid);
	}

	PQclear(result);

	return uid;
}

/**
 *	getkeysigs - Gets a linked list of the signatures on a key.
 *	@keyid: The keyid to get the sigs for.
 *	@revoked: If the key is revoked.
 *
 *	This function gets the list of signatures on a key. Used for key 
 *	indexing and doing stats bits.
 */
struct ll *getkeysigs(uint64_t keyid, bool *revoked)
{
	struct ll *sigs = NULL;
	PGresult *result = NULL;
	uint64_t signer;
	char statement[1024];
	int i, j;
	int numsigs = 0;
	bool intrans = false;
	char *str;

	if (!intrans) {
		result = PQexec(dbconn, "BEGIN");
		PQclear(result);
	}

	snprintf(statement, 1023,
		"SELECT DISTINCT signer FROM onak_sigs WHERE signee = '%llX'",
		keyid);
	result = PQexec(dbconn, statement);

	if (PQresultStatus(result) == PGRES_TUPLES_OK) {
		numsigs = PQntuples(result);
		for (i = 0; i < numsigs;  i++) {
			j = 0;
			signer = 0;
			str = PQgetvalue(result, i, 0);
			while (str[j] != 0) {
				signer <<= 4;
				if (str[j] >= '0' && str[j] <= '9') {
					signer += str[j] - '0';
				} else {
					signer += str[j] - 'A' + 10;
				}
				j++;
			}
			sigs = lladd(sigs, createandaddtohash(signer));
		}
	} else if (PQresultStatus(result) != PGRES_TUPLES_OK) {
		logthing(LOGTHING_ERROR, "Problem retrieving key from DB.");
	}

	PQclear(result);

	if (!intrans) {
		result = PQexec(dbconn, "COMMIT");
		PQclear(result);
	}

	/*
	 * TODO: What do we do about revocations? We don't have the details
	 * stored in a separate table, so we'd have to grab the key and decode
	 * it, which we're trying to avoid by having a signers table.
	 */
	if (revoked != NULL) {
		*revoked = false;
	}
	
	return sigs;
}

/**
 *	dumpdb - dump the key database
 *	@filenamebase: The base filename to use for the dump.
 *
 *	Dumps the database into one or more files, which contain pure OpenPGP
 *	that can be reimported into onak or gpg. filenamebase provides a base
 *	file name for the dump; several files may be created, all of which will
 *	begin with this string and then have a unique number and a .pgp
 *	extension.
 *          */
int dumpdb(char *filenamebase)
{
	return 0;
}

/*
 * Include the basic keydb routines.
 */
#define NEED_GETFULLKEYID 1
#include "keydb.c"
