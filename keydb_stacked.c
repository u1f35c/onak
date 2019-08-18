/*
 * keydb_stacked.c - backend that stacks other backends together
 *
 * Copyright 2016 Jonathan McDowell <noodles@earth.li>
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

#include "cleankey.h"
#include "keydb.h"
#include "keystructs.h"
#include "ll.h"
#include "log.h"
#include "onak-conf.h"

struct onak_stacked_dbctx {
	struct ll *backends;
	bool store_on_fallback;
};

/*
 * The following functions only apply to the first backend.
 */

static bool stacked_starttrans(struct onak_dbctx *dbctx)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend =
			(struct onak_dbctx *) privctx->backends->object;

	return backend->starttrans(backend);
}

static void stacked_endtrans(struct onak_dbctx *dbctx)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend =
			(struct onak_dbctx *) privctx->backends->object;

	backend->starttrans(backend);
}

static int stacked_store_key(struct onak_dbctx *dbctx,
		struct openpgp_publickey *publickey, bool intrans,
		bool update)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend =
			(struct onak_dbctx *) privctx->backends->object;

	return backend->store_key(backend,
			publickey, intrans, update);
}

static int stacked_delete_key(struct onak_dbctx *dbctx,
		struct openpgp_fingerprint *fp,
		bool intrans)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend =
			(struct onak_dbctx *) privctx->backends->object;

	return backend->delete_key(backend,
			fp, intrans);
}

static int stacked_update_keys(struct onak_dbctx *dbctx,
		struct openpgp_publickey **keys,
		struct keyarray *blacklist,
		bool sendsync)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend =
			(struct onak_dbctx *) privctx->backends->object;

	return backend->update_keys(backend, keys, blacklist, sendsync);
}

static int stacked_iterate_keys(struct onak_dbctx *dbctx,
		void (*iterfunc)(void *ctx, struct openpgp_publickey *key),
		void *ctx)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend =
			(struct onak_dbctx *) privctx->backends->object;

	return backend->iterate_keys(backend, iterfunc, ctx);
}

static void store_on_fallback(struct onak_stacked_dbctx *privctx,
		struct openpgp_publickey *publickey, bool intrans)
{
	struct onak_dbctx *backend =
			(struct onak_dbctx *) privctx->backends->object;
	struct openpgp_publickey *curkey;

	cleankeys(&publickey, config.clean_policies);
	/*
	 * If we walked the stack at all, store the key in the first
	 * backend if configured to do so. It's not an update as we
	 * know it's not there or we wouldn't have fallen back.
	 */
	for (curkey = publickey; curkey != NULL; curkey = curkey->next) {
		backend->store_key(backend, curkey, intrans, false);
	}
}

/*
 * The functions below will walk along the backend stack until they
 * reach the end or get a successful result.
 */

static int stacked_fetch_key_id(struct onak_dbctx *dbctx, uint64_t keyid,
		struct openpgp_publickey **publickey, bool intrans)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend;
	struct ll *cur;
	int res = 0;

	for (cur = privctx->backends; cur != NULL && res == 0;
			cur = cur->next) {
		backend = (struct onak_dbctx *) cur->object;
		res = backend->fetch_key_id(backend, keyid, publickey,
				intrans);
	}

	if (privctx->store_on_fallback && cur != privctx->backends) {
		store_on_fallback(privctx, *publickey, intrans);
	}

	return res;
}

static int stacked_fetch_key_fp(struct onak_dbctx *dbctx,
		struct openpgp_fingerprint *fingerprint,
		struct openpgp_publickey **publickey, bool intrans)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend;
	struct ll *cur;
	int res = 0;

	for (cur = privctx->backends; cur != NULL && res == 0;
			cur = cur->next) {
		backend = (struct onak_dbctx *) cur->object;
		res = backend->fetch_key_fp(backend, fingerprint, publickey,
				intrans);
	}

	if (privctx->store_on_fallback && cur != privctx->backends) {
		store_on_fallback(privctx, *publickey, intrans);
	}

	return res;
}

static int stacked_fetch_key_text(struct onak_dbctx *dbctx,
		const char *search,
		struct openpgp_publickey **publickey)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend;
	struct ll *cur;
	int res = 0;

	for (cur = privctx->backends; cur != NULL && res == 0;
			cur = cur->next) {
		backend = (struct onak_dbctx *) cur->object;
		res = backend->fetch_key_text(backend, search, publickey);
	}

	if (privctx->store_on_fallback && cur != privctx->backends) {
		store_on_fallback(privctx, *publickey, false);
	}

	return res;
}

static int stacked_fetch_key_skshash(struct onak_dbctx *dbctx,
		const struct skshash *hash,
		struct openpgp_publickey **publickey)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend;
	struct ll *cur;
	int res = 0;

	for (cur = privctx->backends; cur != NULL && res == 0;
			cur = cur->next) {
		backend = (struct onak_dbctx *) cur->object;
		res = backend->fetch_key_skshash(backend, hash, publickey);
	}

	if (privctx->store_on_fallback && cur != privctx->backends) {
		store_on_fallback(privctx, *publickey, false);
	}

	return res;
}

/*
 * Include the basic keydb routines so we can use them for fall back.
 * For all of the following we try the top keydb backend and if that doesn't
 * have answer fall back to the generics, which will do a retrieve from a
 * backend further down the stack, then a fallback store.
 */
#define NEED_KEYID2UID 1
#define NEED_GETKEYSIGS 1
#define NEED_UPDATEKEYS 1
#include "keydb.c"

static struct ll *stacked_getkeysigs(struct onak_dbctx *dbctx,
		uint64_t keyid, bool *revoked)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend =
			(struct onak_dbctx *) privctx->backends->object;
	struct ll *res;

	res = backend->getkeysigs(backend, keyid, revoked);
	if (res == NULL) {
		res = generic_getkeysigs(dbctx, keyid, revoked);
	}

	return res;
}

static struct ll *stacked_cached_getkeysigs(struct onak_dbctx *dbctx,
		uint64_t keyid)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend =
			(struct onak_dbctx *) privctx->backends->object;
	struct ll *res;

	res = backend->cached_getkeysigs(backend, keyid);
	if (res == NULL) {
		res = generic_cached_getkeysigs(dbctx, keyid);
	}

	return res;
}

static char *stacked_keyid2uid(struct onak_dbctx *dbctx,
			uint64_t keyid)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend =
			(struct onak_dbctx *) privctx->backends->object;
	char *res = NULL;

	res = backend->keyid2uid(backend, keyid);
	if (!res) {
		res = generic_keyid2uid(dbctx, keyid);
	}

	return res;
}

static void stacked_cleanupdb(struct onak_dbctx *dbctx)
{
	struct onak_stacked_dbctx *privctx =
			(struct onak_stacked_dbctx *) dbctx->priv;
	struct onak_dbctx *backend;
	struct ll *cur;
	int res = 0;

	for (cur = privctx->backends; cur != NULL && res == 0;
			cur = cur->next) {
		backend = (struct onak_dbctx *) cur->object;
		backend->cleanupdb(backend);
	}

	if (dbctx->priv != NULL) {
		free(dbctx->priv);
		dbctx->priv = NULL;
	}

	if (dbctx != NULL) {
		free(dbctx);
	}
}

struct onak_dbctx *keydb_stacked_init(struct onak_db_config *dbcfg,
		bool readonly)
{
	struct onak_dbctx *dbctx;
	struct onak_stacked_dbctx *privctx;
	struct onak_dbctx *backend;
	struct onak_db_config *backend_cfg;
	char *backend_name, *saveptr = NULL;

	if (dbcfg == NULL) {
		logthing(LOGTHING_CRITICAL,
			"No backend database configuration supplied.");
		return NULL;
	}

	dbctx = malloc(sizeof(struct onak_dbctx));

	if (dbctx == NULL) {
		return NULL;
	}

	dbctx->config = dbcfg;
	dbctx->priv = privctx = malloc(sizeof(struct onak_stacked_dbctx));
	if (dbctx->priv == NULL) {
		free(dbctx);
		return (NULL);
	}

	/* TODO: Make configurable? */
	privctx->store_on_fallback = true;
	privctx->backends = NULL;

	backend_name = strtok_r(dbcfg->location, ":", &saveptr);
	while (backend_name != NULL) {
		backend_cfg = find_db_backend_config(config.backends,
				backend_name);
		if (backend_cfg == NULL) {
			logthing(LOGTHING_CRITICAL,
				"Couldn't find configuration for %s backend",
				backend_name);
			stacked_cleanupdb(dbctx);
			return NULL;
		}
		logthing(LOGTHING_INFO, "Loading stacked backend: %s",
				backend_cfg->name);

		backend = config.dbinit(backend_cfg, readonly);
		privctx->backends = lladdend(privctx->backends, backend);

		backend_name = strtok_r(NULL, ":", &saveptr);
	}

	if (privctx->backends != NULL) {
		dbctx->cleanupdb = stacked_cleanupdb;
		dbctx->starttrans = stacked_starttrans;
		dbctx->endtrans = stacked_endtrans;
		dbctx->fetch_key_id = stacked_fetch_key_id;
		dbctx->fetch_key_fp = stacked_fetch_key_fp;
		dbctx->fetch_key_text = stacked_fetch_key_text;
		dbctx->fetch_key_skshash = stacked_fetch_key_skshash;
		dbctx->store_key = stacked_store_key;
		dbctx->update_keys = stacked_update_keys;
		dbctx->delete_key = stacked_delete_key;
		dbctx->getkeysigs = stacked_getkeysigs;
		dbctx->cached_getkeysigs = stacked_cached_getkeysigs;
		dbctx->keyid2uid = stacked_keyid2uid;
		dbctx->iterate_keys = stacked_iterate_keys;
	}

	return dbctx;
}
