/*
 * keydb_dynamic.c - backend that can load the other backends
 *
 * Copyright 2005 Brett Parker <iDunno@sommitrealweird.co.uk>
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

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include "decodekey.h"
#include "hash.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "log.h"
#include "mem.h"
#include "merge.h"
#include "onak-conf.h"
#include "openpgp.h"
#include "parsekey.h"
#include "sendsync.h"

struct onak_dynamic_dbctx {
	struct onak_dbctx *loadeddbctx;
	void              *backend_handle;
};

static bool dynamic_starttrans(struct onak_dbctx *dbctx)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	return privctx->loadeddbctx->starttrans(privctx->loadeddbctx);
}

static void dynamic_endtrans(struct onak_dbctx *dbctx)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	privctx->loadeddbctx->endtrans(privctx->loadeddbctx);
}

static int dynamic_fetch_key_id(struct onak_dbctx *dbctx, uint64_t keyid,
		struct openpgp_publickey **publickey, bool intrans)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	return privctx->loadeddbctx->fetch_key_id(privctx->loadeddbctx, keyid,
			publickey, intrans);
}

static int dynamic_fetch_key_fp(struct onak_dbctx *dbctx,
		struct openpgp_fingerprint *fingerprint,
		struct openpgp_publickey **publickey, bool intrans)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	return privctx->loadeddbctx->fetch_key_fp(privctx->loadeddbctx,
			fingerprint, publickey, intrans);
}

static int dynamic_fetch_key_text(struct onak_dbctx *dbctx,
		const char *search,
		struct openpgp_publickey **publickey)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	return privctx->loadeddbctx->fetch_key_text(privctx->loadeddbctx,
			search, publickey);
}

static int dynamic_fetch_key_skshash(struct onak_dbctx *dbctx,
		const struct skshash *hash,
		struct openpgp_publickey **publickey)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	return privctx->loadeddbctx->fetch_key_skshash(privctx->loadeddbctx,
			hash, publickey);
}

static int dynamic_store_key(struct onak_dbctx *dbctx,
		struct openpgp_publickey *publickey, bool intrans,
		bool update)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	return privctx->loadeddbctx->store_key(privctx->loadeddbctx,
			publickey, intrans, update);
}

static int dynamic_delete_key(struct onak_dbctx *dbctx,
		struct openpgp_fingerprint *fp,
		bool intrans)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	return privctx->loadeddbctx->delete_key(privctx->loadeddbctx,
			fp, intrans);
}

static int dynamic_update_keys(struct onak_dbctx *dbctx,
		struct openpgp_publickey **keys, bool sendsync)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	return privctx->loadeddbctx->update_keys(privctx->loadeddbctx,
			keys, sendsync);
}

static struct ll *dynamic_getkeysigs(struct onak_dbctx *dbctx,
		uint64_t keyid, bool *revoked)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	return privctx->loadeddbctx->getkeysigs(privctx->loadeddbctx,
			keyid, revoked);
}

static struct ll *dynamic_cached_getkeysigs(struct onak_dbctx *dbctx,
		uint64_t keyid)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	return privctx->loadeddbctx->cached_getkeysigs(privctx->loadeddbctx,
			keyid);
}

static char *dynamic_keyid2uid(struct onak_dbctx *dbctx,
			uint64_t keyid)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	return privctx->loadeddbctx->keyid2uid(privctx->loadeddbctx,
			keyid);
}

static int dynamic_iterate_keys(struct onak_dbctx *dbctx,
		void (*iterfunc)(void *ctx, struct openpgp_publickey *key),
		void *ctx)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	return privctx->loadeddbctx->iterate_keys(privctx->loadeddbctx,
			iterfunc, ctx);
}

static void dynamic_cleanupdb(struct onak_dbctx *dbctx)
{
	struct onak_dynamic_dbctx *privctx =
			(struct onak_dynamic_dbctx *) dbctx->priv;

	if (privctx->loadeddbctx != NULL) {
		if (privctx->loadeddbctx->cleanupdb != NULL) {
			privctx->loadeddbctx->cleanupdb(privctx->loadeddbctx);
			privctx->loadeddbctx = NULL;
		}
	}

	if (privctx->backend_handle != NULL) {
		dlclose(privctx->backend_handle);
		privctx->backend_handle = NULL;
	}

	if (dbctx->priv != NULL) {
		free(dbctx->priv);
		dbctx->priv = NULL;
	}

	if (dbctx != NULL) {
		free(dbctx);
	}
}

struct onak_dbctx *keydb_dynamic_init(struct onak_db_config *dbcfg,
		bool readonly)
{
	struct onak_dbctx *dbctx;
	char *soname;
	char *initname;
	struct onak_dbctx *(*backend_init)(struct onak_db_config *, bool);
	struct onak_dynamic_dbctx *privctx;
	char *type;

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
	dbctx->priv = privctx = malloc(sizeof(struct onak_dynamic_dbctx));
	if (dbctx->priv == NULL) {
		free(dbctx);
		return (NULL);
	}

	type = dbcfg->type;
	if (config.use_keyd) {
		type = "keyd";
	}

	if (!config.db_backend) {
		logthing(LOGTHING_CRITICAL, "No database backend defined.");
		exit(EXIT_FAILURE);
	}

	if (config.backends_dir == NULL) {
		soname = malloc(strlen(type)
			+ strlen("./libkeydb_")
			+ strlen(".so")
			+ 1);

		sprintf(soname, "./libkeydb_%s.so", type);
	} else {
		soname = malloc(strlen(type)
			+ strlen("/libkeydb_")
			+ strlen(".so")
			+ strlen(config.backends_dir)
			+ 1);

		sprintf(soname, "%s/libkeydb_%s.so", config.backends_dir,
			type);
	}

	logthing(LOGTHING_INFO, "Loading dynamic backend: %s", soname);

	privctx->backend_handle = dlopen(soname, RTLD_LAZY);
	if (privctx->backend_handle == NULL) {
		logthing(LOGTHING_CRITICAL,
				"Failed to open handle to library '%s': %s",
				soname, dlerror());
		free(soname);
		soname = NULL;
		exit(EXIT_FAILURE);
	}

	initname = malloc(strlen(config.db_backend)
			+ strlen("keydb_")
			+ strlen("_init")
			+ 1);
	sprintf(initname, "keydb_%s_init", type);

	*(void **) (&backend_init) = dlsym(privctx->backend_handle, initname);
	free(initname);

	if (backend_init == NULL) {
		logthing(LOGTHING_CRITICAL,
				"Failed to find dbfuncs structure in library "
				"'%s' : %s", soname, dlerror());
		free(soname);
		soname = NULL;
		exit(EXIT_FAILURE);
	}

	privctx->loadeddbctx = backend_init(dbcfg, readonly);

	if (privctx->loadeddbctx == NULL) {
		logthing(LOGTHING_CRITICAL,
				"Failed to initialise dynamic backend: %s",
				soname);
		free(soname);
		soname = NULL;
		exit(EXIT_FAILURE);
	}
	free(soname);
	soname = NULL;

	if (privctx->loadeddbctx != NULL) {
		dbctx->cleanupdb = dynamic_cleanupdb;
		dbctx->starttrans = dynamic_starttrans;
		dbctx->endtrans = dynamic_endtrans;
		dbctx->fetch_key_id = dynamic_fetch_key_id;
		dbctx->fetch_key_fp = dynamic_fetch_key_fp;
		dbctx->fetch_key_text = dynamic_fetch_key_text;
		dbctx->fetch_key_skshash = dynamic_fetch_key_skshash;
		dbctx->store_key = dynamic_store_key;
		dbctx->update_keys = dynamic_update_keys;
		dbctx->delete_key = dynamic_delete_key;
		dbctx->getkeysigs = dynamic_getkeysigs;
		dbctx->cached_getkeysigs = dynamic_cached_getkeysigs;
		dbctx->keyid2uid = dynamic_keyid2uid;
		dbctx->iterate_keys = dynamic_iterate_keys;
	}

	return dbctx;
}
