/*
 * keydb_dummy.c - skeleton backend that does nothing
 *
 * Copyright 2025 Jonathan McDowell <noodles@earth.li>
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keydb.h"
#include "keystructs.h"
#include "ll.h"
#include "log.h"
#include "onak-conf.h"

/**
 * @brief Private per-instance context for dummy database backend
 */
struct onak_dummy_dbctx {
};

/**
 * @brief Start a transaction.
 *
 * Start a transaction. Intended to be used if we're about to perform many
 * operations on the database to help speed it all up, or if we want
 * something to only succeed if all relevant operations are successful.
 *
 * @return Boolean indicating if we started the transaction successfully.
 */
static bool dummy_starttrans(struct onak_dbctx *dbctx)
{
	return true;
}

/**
 * @brief End a transaction.
 *
 * Ends a transaction.
 */
static void dummy_endtrans(struct onak_dbctx *dbctx)
{
	return;
}

/**
 * @brief Takes a key and stores it.
 * @param publickey A pointer to the public key to store.
 * @param intrans If we're already in a transaction.
 * @param update If true the key exists and should be updated.
 *
 * This function stores a public key in whatever storage mechanism we are
 * using. intrans indicates if we're already in a transaction so don't
 * need to start one. update indicates if the key already exists and is
 * just being updated.
 */
static int dummy_store_key(struct onak_dbctx *dbctx,
		struct openpgp_publickey *publickey, bool intrans,
		bool update)
{
	struct onak_dummy_dbctx *privctx = (struct onak_dummy_dbctx *) dbctx->priv;

	if (!intrans) {
		dummy_starttrans(dbctx);
	}

	if (!intrans) {
		dummy_endtrans(dbctx);
	}

	return 0;
}

/**
 * @brief Given a keyid delete the key from storage.
 * @param fp The fingerprint of the key to delete.
 * @param intrans If we're already in a transaction.
 *
 * This function deletes a public key from whatever storage mechanism we
 * are using. Returns 0 if the key existed.
 */
static int dummy_delete_key(struct onak_dbctx *dbctx,
		struct openpgp_fingerprint *fp,
		bool intrans)
{
	struct onak_dummy_dbctx *privctx = (struct onak_dummy_dbctx *) dbctx->priv;

	if (!intrans) {
		dummy_starttrans(dbctx);
	}

	if (!intrans) {
		dummy_endtrans(dbctx);
	}

	return 0;
}

/**
 * @brief Takes a list of public keys and updates them in the DB.
 * @param keys The keys to update in the DB.
 * @param blacklist A keyarray of fingerprints that shouldn't be added.
 * @updateonly: Only update existing keys, don't add new ones.
 * @param sendsync If we should send a keysync mail.
 *
 * Takes a list of keys and adds them to the database, merging them with
 * the key in the database if it's already present there. The key list is
 * update to contain the minimum set of updates required to get from what
 * we had before to what we have now (ie the set of data that was added to
 * the DB). Returns the number of entirely new keys added.
 *
 * If sendsync is true then we send out a keysync mail to our sync peers
 * with the update.
 */
static int dummy_update_keys(struct onak_dbctx *dbctx,
		struct openpgp_publickey **keys,
		struct keyarray *blacklist,
		bool updateonly,
		bool sendsync)
{
	struct onak_dummy_dbctx *privctx = (struct onak_dummy_dbctx *) dbctx->priv;

	return 0;
}

/**
 * @brief call a function once for each key in the db.
 * @param iterfunc The function to call.
 * @param ctx A context pointer
 *
 * Calls iterfunc once for each key in the database. ctx is passed
 * unaltered to iterfunc. This function is intended to aid database dumps
 * and statistic calculations.
 *
 * Returns the number of keys we iterated over.
 */
static int dummy_iterate_keys(struct onak_dbctx *dbctx,
		void (*iterfunc)(void *ctx, struct openpgp_publickey *key),
		void *ctx)
{
	struct onak_dummy_dbctx *privctx = (struct onak_dummy_dbctx *) dbctx->priv;

	return 0;
}

/**
 * @brief Given a fingerprint fetch the key from storage.
 * @param fp The fingerprint to fetch.
 * @param fpsize Number of bytes in the fingerprint (16 for v3, 20 for v4)
 * @param publickey A pointer to a structure to return the key in.
 * @param intrans  If we're already in a transaction.
 * @return Number of keys returned.
 *
 * This function returns a public key from whatever storage mechanism we
 * are using. This only searches for the fingerprint of the primary key
 * and will thus only ever return at most a single key.
 */
static int dummy_fetch_key(struct onak_dbctx *dbctx,
		struct openpgp_fingerprint *fingerprint,
		struct openpgp_publickey **publickey, bool intrans)
{
	struct onak_dummy_dbctx *privctx = (struct onak_dummy_dbctx *) dbctx->priv;

	if (!intrans) {
		dummy_starttrans(dbctx);
	}

	if (!intrans) {
		dummy_endtrans(dbctx);
	}

	return 0;
}

/**
 * @brief Given a fingerprint fetch the key from storage.
 * @param fp The fingerprint to fetch.
 * @param fpsize Number of bytes in the fingerprint (16 for v3, 20 for v4)
 * @param publickey A pointer to a structure to return the key in.
 * @param intrans  If we're already in a transaction.
 * @return Number of keys returned.
 *
 * This function returns a public key from whatever storage mechanism we
 * are using. Although the fingerprint should be unique this function may
 * also search subkeys, which could be bound to multiple primary keys. As
 * a result multiple keys may be returned.
 */
static int dummy_fetch_key_fp(struct onak_dbctx *dbctx,
		struct openpgp_fingerprint *fingerprint,
		struct openpgp_publickey **publickey, bool intrans)
{
	struct onak_dummy_dbctx *privctx = (struct onak_dummy_dbctx *) dbctx->priv;

	if (!intrans) {
		dummy_starttrans(dbctx);
	}

	if (!intrans) {
		dummy_endtrans(dbctx);
	}

	return 0;
}

/**
 * @brief Given a keyid fetch the key from storage.
 * @param keyid The keyid to fetch.
 * @param publickey A pointer to a structure to return the key in.
 * @param intrans  If we're already in a transaction.
 * @return Number of keys returned.
 *
 * This function returns a public key from whatever storage mechanism we
 * are using. It may return multiple keys in the case where there are
 * colliding keyids.
 */
static int dummy_fetch_key_id(struct onak_dbctx *dbctx, uint64_t keyid,
		struct openpgp_publickey **publickey, bool intrans)
{
	struct onak_dummy_dbctx *privctx = (struct onak_dummy_dbctx *) dbctx->priv;

	if (!intrans) {
		dummy_starttrans(dbctx);
	}

	if (!intrans) {
		dummy_endtrans(dbctx);
	}

	return 0;
}

/**
 * @brief Tries to find the keys that contain the supplied text.
 * @param search The text to search for.
 * @param publickey A pointer to a structure to return the key in.
 * @return Number of keys returned.
 *
 * This function searches for the supplied text and returns the keys that
 * contain it. It is likely it will return multiple keys.
 */
static int dummy_fetch_key_text(struct onak_dbctx *dbctx,
		const char *search,
		struct openpgp_publickey **publickey)
{
	struct onak_dummy_dbctx *privctx = (struct onak_dummy_dbctx *) dbctx->priv;

	return 0;
}

/**
 * @brief Tries to find the keys from an SKS hash
 * @param hash The hash to search for.
 * @param publickey A pointer to a structure to return the key in.
 * @return Number of keys returned.
 *
 * This function looks for the key that is referenced by the supplied
 * SKS hash and returns it.
 */
static int dummy_fetch_key_skshash(struct onak_dbctx *dbctx,
		const struct skshash *hash,
		struct openpgp_publickey **publickey)
{
	struct onak_dummy_dbctx *privctx = (struct onak_dummy_dbctx *) dbctx->priv;

	return 0;
}

/**
 * @brief Gets a linked list of the signatures on a key.
 * @param keyid The keyid to get the sigs for.
 * @param revoked Is the key revoked?
 *
 * This function gets the list of signatures on a key. Used for key
 * indexing and doing stats bits. If revoked is non-NULL then if the key
 * is revoked it's set to true.
 */
static struct ll *dummy_getkeysigs(struct onak_dbctx *dbctx,
		uint64_t keyid, bool *revoked)
{
	struct onak_dummy_dbctx *privctx = (struct onak_dummy_dbctx *) dbctx->priv;

	return NULL;
}

/**
 * @brief Gets the signatures on a key.
 * @param keyid The key we want the signatures for.
 *
 * This function gets the signatures on a key. It's the same as the
 * getkeysigs function above except we use the hash module to cache them.
 */
static struct ll *dummy_cached_getkeysigs(struct onak_dbctx *dbctx,
		uint64_t keyid)
{
	struct onak_dummy_dbctx *privctx = (struct onak_dummy_dbctx *) dbctx->priv;

	return NULL;
}

/**
 * @brief Takes a keyid and returns the primary UID for it.
 * @param keyid The keyid to lookup.
 *
 * This function returns a UID for the given key. Returns NULL if the key
 * isn't found.
 */
static char *dummy_keyid2uid(struct onak_dbctx *dbctx,
			uint64_t keyid)
{
	struct onak_dummy_dbctx *privctx = (struct onak_dummy_dbctx *) dbctx->priv;

	return NULL;
}

/**
 * @brief De-initialize the key database.
 *
 * This function should be called upon program exit to allow the DB to
 * cleanup after itself.
 */
static void dummy_cleanupdb(struct onak_dbctx *dbctx)
{
	struct onak_dummy_dbctx *privctx = (struct onak_dummy_dbctx *) dbctx->priv;

	free(privctx);
	dbctx->priv = NULL;
	free(dbctx);

	return;
}

struct onak_dbctx *keydb_dummy_init(struct onak_db_config *dbcfg,
		bool readonly)
{
	struct onak_dummy_dbctx *privctx;
	struct onak_dbctx *dbctx;

	if (dbcfg == NULL) {
		logthing(LOGTHING_CRITICAL,
			"No backend database configuration supplied.");
		return NULL;
	}

	dbctx = calloc(1, sizeof(struct onak_dbctx));
	if (dbctx == NULL) {
		return NULL;
	}

	dbctx->priv = privctx = calloc(1, sizeof(*privctx));
	if (privctx == NULL) {
		free(dbctx);
		return NULL;
	}

	dbctx->config = dbcfg;

	dbctx->cleanupdb = dummy_cleanupdb;
	dbctx->starttrans = dummy_starttrans;
	dbctx->endtrans = dummy_endtrans;
	dbctx->fetch_key = dummy_fetch_key;
	dbctx->fetch_key_fp = dummy_fetch_key_fp;
	dbctx->fetch_key_id = dummy_fetch_key_id;
	dbctx->fetch_key_text = dummy_fetch_key_text;
	dbctx->fetch_key_skshash = dummy_fetch_key_skshash;
	dbctx->store_key = dummy_store_key;
	dbctx->update_keys = dummy_update_keys;
	dbctx->delete_key = dummy_delete_key;
	dbctx->getkeysigs = dummy_getkeysigs;
	dbctx->cached_getkeysigs = dummy_cached_getkeysigs;
	dbctx->keyid2uid = dummy_keyid2uid;
	dbctx->iterate_keys = dummy_iterate_keys;

	return dbctx;
}
