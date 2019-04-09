/*
 * keydb_pg.c - Routines to store and fetch keys in a PostGres database.
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
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <postgresql/libpq-fe.h>
#include <postgresql/libpq/libpq-fs.h>

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

struct pg_fc_ctx {
	PGconn *dbconn;
	int fd;
};

/**
 *	keydb_fetchchar - Fetches a char from a file.
 */
static int keydb_fetchchar(void *_ctx, size_t count, void *c)
{
	struct pg_fc_ctx *ctx = (struct pg_fc_ctx *) _ctx;

	return (!lo_read(ctx->dbconn, ctx->fd, (char *) c, count));
}

/**
 *	keydb_putchar - Puts a char to a file.
 */
static int keydb_putchar(void *_ctx, size_t count, void *c)
{
	struct pg_fc_ctx *ctx = (struct pg_fc_ctx *) _ctx;

	return !(lo_write(ctx->dbconn, ctx->fd, (char *) c, count));
}

/**
 *	starttrans - Start a transaction.
 *
 *	Start a transaction. Intended to be used if we're about to perform many
 *	operations on the database to help speed it all up, or if we want
 *	something to only succeed if all relevant operations are successful.
 */
static bool pg_starttrans(struct onak_dbctx *dbctx)
{
	PGconn *dbconn = (PGconn *) dbctx->priv;
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
static void pg_endtrans(struct onak_dbctx *dbctx)
{
	PGconn *dbconn = (PGconn *) dbctx->priv;
	PGresult *result = NULL;

	result = PQexec(dbconn, "COMMIT");
	PQclear(result);

	return;
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
static int pg_fetch_key_id(struct onak_dbctx *dbctx,
		uint64_t keyid,
		struct openpgp_publickey **publickey,
		bool intrans)
{
	struct openpgp_packet_list *packets = NULL;
	PGconn *dbconn = (PGconn *) dbctx->priv;
	PGresult *result = NULL;
	char *oids = NULL;
	char statement[1024];
	int i = 0;
	int numkeys = 0;
	Oid key_oid;
	struct pg_fc_ctx fcctx;

	if (!intrans) {
		result = PQexec(dbconn, "BEGIN");
		PQclear(result);
	}
	
	if (keyid > 0xFFFFFFFF) {
		snprintf(statement, 1023,
			"SELECT keydata FROM onak_keys WHERE keyid = '%"
			PRIX64 "'",
			keyid);
	} else {
		snprintf(statement, 1023,
			"SELECT keydata FROM onak_keys WHERE keyid "
			"LIKE '%%%" PRIX64 "'",
			keyid);
	}
	result = PQexec(dbconn, statement);

	if (PQresultStatus(result) == PGRES_TUPLES_OK) {
		numkeys = PQntuples(result);
		for (i = 0; i < numkeys && numkeys <= config.maxkeys; i++) {
			oids = PQgetvalue(result, i, 0);
			key_oid = (Oid) atoi(oids);

			fcctx.fd = lo_open(dbconn, key_oid, INV_READ);
			if (fcctx.fd < 0) {
				logthing(LOGTHING_ERROR,
						"Can't open large object.");
			} else {
				fcctx.dbconn = dbconn;
				read_openpgp_stream(keydb_fetchchar, &fcctx,
						&packets, 0);
				parse_keys(packets, publickey);
				lo_close(dbconn, fcctx.fd);
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
static int pg_fetch_key_text(struct onak_dbctx *dbctx,
		const char *search,
		struct openpgp_publickey **publickey)
{
	struct openpgp_packet_list *packets = NULL;
	PGconn *dbconn = (PGconn *) dbctx->priv;
	PGresult *result = NULL;
	char *oids = NULL;
	char statement[1024];
	int i = 0;
	int numkeys = 0;
	Oid key_oid;
	char *newsearch = NULL;
	struct pg_fc_ctx fcctx;

	result = PQexec(dbconn, "BEGIN");
	PQclear(result);

	newsearch = malloc(strlen(search) * 2 + 1);
	memset(newsearch, 0, strlen(search) * 2 + 1);
	PQescapeStringConn(dbconn, newsearch, search, strlen(search), NULL);
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

			fcctx.fd = lo_open(dbconn, key_oid, INV_READ);
			if (fcctx.fd < 0) {
				logthing(LOGTHING_ERROR,
						"Can't open large object.");
			} else {
				fcctx.dbconn = dbconn;
				read_openpgp_stream(keydb_fetchchar, &fcctx,
						&packets,
						0);
				parse_keys(packets, publickey);
				lo_close(dbconn, fcctx.fd);
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
 *	delete_key - Given a keyid delete the key from storage.
 *	@keyid: The keyid to delete.
 *	@intrans: If we're already in a transaction.
 *
 *	This function deletes a public key from whatever storage mechanism we
 *	are using. Returns 0 if the key existed.
 */
static int pg_delete_key(struct onak_dbctx *dbctx, uint64_t keyid, bool intrans)
{
	PGconn *dbconn = (PGconn *) dbctx->priv;
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
			"SELECT keydata FROM onak_keys WHERE keyid = '%"
			PRIX64 "'",
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
			"DELETE FROM onak_keys WHERE keyid = '%" PRIX64 "'",
			keyid);
		result = PQexec(dbconn, statement);
		PQclear(result);

		snprintf(statement, 1023,
			"DELETE FROM onak_sigs WHERE signee = '%" PRIX64 "'",
			keyid);
		result = PQexec(dbconn, statement);
		PQclear(result);

		snprintf(statement, 1023,
			"DELETE FROM onak_uids WHERE keyid = '%" PRIX64 "'",
			keyid);
		result = PQexec(dbconn, statement);
	} else if (PQresultStatus(result) != PGRES_TUPLES_OK) {
		logthing(LOGTHING_ERROR,
				"Problem retrieving key (%" PRIX64
				") from DB.",
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
static int pg_store_key(struct onak_dbctx *dbctx,
		struct openpgp_publickey *publickey, bool intrans,
		bool update)
{
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct openpgp_publickey *next = NULL;
	struct openpgp_signedpacket_list *curuid = NULL;
	PGconn *dbconn = (PGconn *) dbctx->priv;
	PGresult *result = NULL;
	char statement[1024];
	Oid key_oid;
	char **uids = NULL;
	char *primary = NULL;
	char *safeuid = NULL;
	int i;
	uint64_t keyid;
	struct pg_fc_ctx fcctx;

	if (!intrans) {
		result = PQexec(dbconn, "BEGIN");
		PQclear(result);
	}

	if (get_keyid(publickey, &keyid) != ONAK_E_OK) {
		logthing(LOGTHING_ERROR, "Couldn't find key ID for key.");
		return 0;
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
		pg_delete_key(dbctx, keyid, true);
	}

	next = publickey->next;
	publickey->next = NULL;
	flatten_publickey(publickey, &packets, &list_end);
	publickey->next = next;
		
	key_oid = lo_creat(dbconn, INV_READ | INV_WRITE);
	if (key_oid == 0) {
		logthing(LOGTHING_ERROR, "Can't create key OID");
	} else {
		fcctx.fd = lo_open(dbconn, key_oid, INV_WRITE);
		fcctx.dbconn = dbconn;
		write_openpgp_stream(keydb_putchar, &fcctx, packets);
		lo_close(dbconn, fcctx.fd);
	}
	free_packet_list(packets);
	packets = NULL;

	snprintf(statement, 1023, 
			"INSERT INTO onak_keys (keyid, keydata) VALUES "
			"('%" PRIX64 "', '%d')", 
			keyid,
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
				PQescapeStringConn(dbconn, safeuid, uids[i],
						strlen(uids[i]), NULL);

				snprintf(statement, 1023,
					"INSERT INTO onak_uids "
					"(keyid, uid, pri) "
					"VALUES	('%" PRIX64 "', '%s', '%c')",
					keyid,
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
				"VALUES ('%" PRIX64 "', '%" PRIX64 "')",
				sig_keyid(packets->packet),
				keyid);
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
 *	keyid2uid - Takes a keyid and returns the primary UID for it.
 *	@keyid: The keyid to lookup.
 */
static char *pg_keyid2uid(struct onak_dbctx *dbctx, uint64_t keyid)
{
	PGconn *dbconn = (PGconn *) dbctx->priv;
	PGresult *result = NULL;
	char statement[1024];
	char *uid = NULL;

	snprintf(statement, 1023,
		"SELECT uid FROM onak_uids WHERE keyid = '%" PRIX64
		"' AND pri = 't'",
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
				"Problem retrieving key (%" PRIX64
				") from DB.",
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
static struct ll *pg_getkeysigs(struct onak_dbctx *dbctx,
			uint64_t keyid, bool *revoked)
{
	struct ll *sigs = NULL;
	PGconn *dbconn = (PGconn *) dbctx->priv;
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
		"SELECT DISTINCT signer FROM onak_sigs WHERE signee = '%"
		PRIX64 "'",
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
static int pg_iterate_keys(struct onak_dbctx *dbctx,
		void (*iterfunc)(void *ctx,
		struct openpgp_publickey *key),	void *ctx)
{
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_publickey *key = NULL;
	PGconn *dbconn = (PGconn *) dbctx->priv;
	PGresult *result = NULL;
	char *oids = NULL;
	int i = 0;
	int numkeys = 0;
	Oid key_oid;
	struct pg_fc_ctx fcctx;

	result = PQexec(dbconn, "SELECT keydata FROM onak_keys;");

	if (PQresultStatus(result) == PGRES_TUPLES_OK) {
		numkeys = PQntuples(result);
		for (i = 0; i < numkeys; i++) {
			oids = PQgetvalue(result, i, 0);
			key_oid = (Oid) atoi(oids);

			fcctx.fd = lo_open(dbconn, key_oid, INV_READ);
			if (fcctx.fd < 0) {
				logthing(LOGTHING_ERROR,
						"Can't open large object.");
			} else {
				fcctx.dbconn = dbconn;
				read_openpgp_stream(keydb_fetchchar, &fcctx,
						&packets, 0);
				parse_keys(packets, &key);
				lo_close(dbconn, fcctx.fd);

				iterfunc(ctx, key);
					
				free_publickey(key);
				key = NULL;
				free_packet_list(packets);
				packets = NULL;
			}
		}
	} else if (PQresultStatus(result) != PGRES_TUPLES_OK) {
		logthing(LOGTHING_ERROR, "Problem retrieving key from DB.");
	}

	PQclear(result);

	return (numkeys);
}

/*
 * Include the basic keydb routines.
 */
#define NEED_GETFULLKEYID 1
#define NEED_UPDATEKEYS 1
#define NEED_GET_FP 1
#include "keydb.c"

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	This function should be called upon program exit to allow the DB to
 *	cleanup after itself.
 */
static void pg_cleanupdb(struct onak_dbctx *dbctx)
{
	PGconn *dbconn = (PGconn *) dbctx->priv;

	PQfinish(dbconn);
	dbconn = NULL;

	free(dbctx);
}

/**
 *	initdb - Initialize the key database.
 *
 *	This function should be called before any of the other functions in
 *	this file are called in order to allow the DB to be initialized ready
 *	for access.
 */
struct onak_dbctx *keydb_pg_init(struct onak_db_config *dbcfg, bool readonly)
{
	struct onak_dbctx *dbctx;
	PGconn *dbconn;

	dbctx = malloc(sizeof(struct onak_dbctx));
	if (dbctx == NULL) {
		return NULL;
	}
	dbctx->config = dbcfg;

	dbconn = PQsetdbLogin(dbcfg->hostname, // host
			NULL, // port
			NULL, // options
			NULL, // tty
			dbcfg->location, // database
			dbcfg->username,  //login
			dbcfg->password); // password

	if (PQstatus(dbconn) == CONNECTION_BAD) {
		logthing(LOGTHING_CRITICAL, "Connection to database failed.");
		logthing(LOGTHING_CRITICAL, "%s", PQerrorMessage(dbconn));
		PQfinish(dbconn);
		dbconn = NULL;
		exit(1);
	}

	dbctx->priv = dbconn;

	dbctx->cleanupdb		= pg_cleanupdb;
	dbctx->starttrans		= pg_starttrans;
	dbctx->endtrans			= pg_endtrans;
	dbctx->fetch_key_id		= pg_fetch_key_id;
	dbctx->fetch_key_fp		= generic_fetch_key_fp;
	dbctx->fetch_key_text		= pg_fetch_key_text;
	dbctx->store_key		= pg_store_key;
	dbctx->update_keys		= generic_update_keys;
	dbctx->delete_key		= pg_delete_key;
	dbctx->getkeysigs		= pg_getkeysigs;
	dbctx->cached_getkeysigs	= generic_cached_getkeysigs;
	dbctx->keyid2uid		= pg_keyid2uid;
	dbctx->getfullkeyid		= generic_getfullkeyid;
	dbctx->iterate_keys		= pg_iterate_keys;

	return dbctx;
}
