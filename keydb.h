/**
 * @file keydb.h
 * @brief Routines to store and fetch keys.
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

#ifndef __KEYDB_H__
#define __KEYDB_H__

#include <stdbool.h>
#include <inttypes.h>

#include "keystructs.h"
#include "ll.h"

/**
 * @brief Context for a database backend
 */
struct onak_dbctx {
/**
 * @brief De-initialize the key database.
 *
 * This function should be called upon program exit to allow the DB to
 * cleanup after itself.
 */
	void (*cleanupdb)(struct onak_dbctx *);

/**
 * @brief Start a transaction.
 *
 * Start a transaction. Intended to be used if we're about to perform many
 * operations on the database to help speed it all up, or if we want
 * something to only succeed if all relevant operations are successful.
 */
	bool (*starttrans)(struct onak_dbctx *);

/**
 * @brief End a transaction.
 *
 * Ends a transaction.
 */
	void (*endtrans)(struct onak_dbctx *);

/**
 * @brief Given a keyid fetch the key from storage.
 * @param keyid The keyid to fetch.
 * @param publickey A pointer to a structure to return the key in.
 * @param intrans  If we're already in a transaction.
 *
 * This function returns a public key from whatever storage mechanism we
 * are using.
 *
 * TODO: What about keyid collisions? Should we use fingerprint instead?
 */
	int (*fetch_key_id)(struct onak_dbctx *,
			uint64_t keyid,
			struct openpgp_publickey **publickey,
			bool intrans);

/**
 * @brief Given a fingerprint fetch the key from storage.
 * @param fp The fingerprint to fetch.
 * @param fpsize Number of bytes in the fingerprint (16 for v3, 20 for v4)
 * @param publickey A pointer to a structure to return the key in.
 * @param intrans  If we're already in a transaction.
 *
 * This function returns a public key from whatever storage mechanism we
 * are using.
 */
	int (*fetch_key_fp)(struct onak_dbctx *,
			struct openpgp_fingerprint *fingerprint,
			struct openpgp_publickey **publickey,
			bool intrans);

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
 *
 * TODO: Do we store multiple keys of the same id? Or only one and replace it?
 */
	int (*store_key)(struct onak_dbctx *,
			struct openpgp_publickey *publickey, bool intrans,
			bool update);

/**
 * @brief Given a keyid delete the key from storage.
 * @param fp The fingerprint of the key to delete.
 * @param intrans If we're already in a transaction.
 *
 * This function deletes a public key from whatever storage mechanism we
 * are using. Returns 0 if the key existed.
 */
	int (*delete_key)(struct onak_dbctx *, struct openpgp_fingerprint *fp,
			bool intrans);

/**
 * @brief Trys to find the keys that contain the supplied text.
 * @param search The text to search for.
 * @param publickey A pointer to a structure to return the key in.
 *
 * This function searches for the supplied text and returns the keys that
 * contain it.
 */
	int (*fetch_key_text)(struct onak_dbctx *, const char *search,
			struct openpgp_publickey **publickey);

/**
 * @brief Tries to find the keys from an SKS hash
 * @param hash The hash to search for.
 * @param publickey A pointer to a structure to return the key in.
 *
 * This function looks for the key that is referenced by the supplied
 * SKS hash and returns it.
 */
	int (*fetch_key_skshash)(struct onak_dbctx *,
			const struct skshash *hash,
			struct openpgp_publickey **publickey);

/**
 * @brief Takes a list of public keys and updates them in the DB.
 * @param keys The keys to update in the DB.
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
	int (*update_keys)(struct onak_dbctx *,
			struct openpgp_publickey **keys, bool sendsync);

/**
 * @brief Takes a keyid and returns the primary UID for it.
 * @param keyid The keyid to lookup.
 *
 * This function returns a UID for the given key. Returns NULL if the key
 * isn't found.
 */
	char * (*keyid2uid)(struct onak_dbctx *, uint64_t keyid);

/**
 * @brief Gets a linked list of the signatures on a key.
 * @param keyid The keyid to get the sigs for.
 * @param revoked Is the key revoked?
 *
 * This function gets the list of signatures on a key. Used for key 
 * indexing and doing stats bits. If revoked is non-NULL then if the key
 * is revoked it's set to true.
 */
	struct ll * (*getkeysigs)(struct onak_dbctx *,
			uint64_t keyid, bool *revoked);

/**
 * @brief Gets the signatures on a key.
 * @param keyid The key we want the signatures for.
 *
 * This function gets the signatures on a key. It's the same as the
 * getkeysigs function above except we use the hash module to cache the
 */
	struct ll * (*cached_getkeysigs)(struct onak_dbctx *,
			uint64_t keyid);

/**
 * @brief Maps a 32 bit key id to a 64 bit one.
 * @param keyid The 32 bit keyid.
 *
 * This function maps a 32 bit key id to the full 64 bit one. It returns the
 * full keyid. If the key isn't found a keyid of 0 is returned.
 */
	uint64_t (*getfullkeyid)(struct onak_dbctx *, uint64_t keyid);

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
	int (*iterate_keys)(struct onak_dbctx *,
			void (*iterfunc)(void *ctx,
			struct openpgp_publickey *key),	void *ctx);

/**
 * @brief Configuration file information for this backend instance
 */
	struct onak_db_config *config;

/**
 * @brief Private backend context information.
 */
	void *priv;
};

#endif /* __KEYDB_H__ */
