/*
 * keydb_hkp.c - Routines to store and fetch keys from another keyserver.
 *
 * Copyright 2013 Jonathan McDowell <noodles@earth.li>
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

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "build-config.h"

#include "armor.h"
#include "charfuncs.h"
#include "keydb.h"
#include "keystructs.h"
#include "log.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"

struct onak_hkp_dbctx {
	struct onak_db_config *config; /* Our DB config info */
	CURL *curl;
	char hkpbase[512];
};

static int hkp_parse_url(struct onak_hkp_dbctx *privctx, const char *url)
{
	char proto[6], host[256];
	unsigned int port;
	int matched;
	int ret = 1;

	proto[0] = host[0] = 0;
	port = 0;

	matched = sscanf(url, "%5[a-z]://%256[a-zA-Z0-9.-]:%u", proto, host,
			&port);
	if (matched < 2) {
		proto[0] = 0;
		sscanf(url, "%256[a-zA-Z0-9.-]:%u", host, &port);
	}

	if (host[0] == 0) {
		logthing(LOGTHING_CRITICAL, "Couldn't parse HKP host: %s",
			url);
		ret = 0;
		goto out;
	}

	if (proto[0] == 0 || !strcmp(proto, "hkp")) {
		if (port == 0) {
			port = 11371;
		}
		snprintf(privctx->hkpbase, sizeof(privctx->hkpbase),
			"http://%s:%u/pks", host, port);
	} else if (!strcmp(proto, "hkps")) {
		if (port == 0) {
			port = 11372;
		}
		snprintf(privctx->hkpbase, sizeof(privctx->hkpbase),
			"https://%s:%u/pks", host, port);
	} else if (strcmp(proto, "http") && strcmp(proto, "https")) {
		logthing(LOGTHING_CRITICAL, "Unknown HKP protocol: %s",
			proto);
		ret = 0;
		goto out;
	} else if (port == 0) {
		snprintf(privctx->hkpbase, sizeof(privctx->hkpbase),
			"%s://%s/pks", proto, host);
	} else {
		snprintf(privctx->hkpbase, sizeof(privctx->hkpbase),
			"%s://%s:%u/pks", proto, host, port);
	}

out:
	return ret;
}

/**
 *	Receive data from a CURL request and process it into a buffer context.
 */
static size_t hkp_curl_recv_data(void *buffer, size_t size, size_t nmemb,
		void *ctx)
{
	buffer_putchar(ctx, nmemb * size, buffer);

	return (nmemb * size);
}

static int hkp_fetch_key_url(struct onak_dbctx *dbctx,
		char *url,
		struct openpgp_publickey **publickey,
		bool intrans)
{
	struct onak_hkp_dbctx *privctx = (struct onak_hkp_dbctx *) dbctx->priv;
	struct openpgp_packet_list *packets = NULL;
	CURLcode res;
	struct buffer_ctx buf;
	int count = 0;

	buf.offset = 0;
	buf.size = 8192;
	buf.buffer = malloc(8192);

	curl_easy_setopt(privctx->curl, CURLOPT_URL, url);
	curl_easy_setopt(privctx->curl, CURLOPT_WRITEFUNCTION,
			hkp_curl_recv_data);
	curl_easy_setopt(privctx->curl, CURLOPT_WRITEDATA, &buf);
	res = curl_easy_perform(privctx->curl);

	if (res == 0) {
		buf.offset = 0;
		dearmor_openpgp_stream(buffer_fetchchar, &buf, &packets);
		count = parse_keys(packets, publickey);
		free_packet_list(packets);
		packets = NULL;
	} else {
		logthing(LOGTHING_ERROR, "Couldn't find key: %s (%d)",
			curl_easy_strerror(res), res);
	}

	free(buf.buffer);
	buf.offset = buf.size = 0;
	buf.buffer = NULL;

	return count;
}

/**
 *	hkp_fetch_key_fp - Given a fingerprint fetch the key from HKP server.
 */
static int hkp_fetch_key_fp(struct onak_dbctx *dbctx,
		struct openpgp_fingerprint *fingerprint,
		struct openpgp_publickey **publickey,
		bool intrans)
{
	struct onak_hkp_dbctx *privctx = (struct onak_hkp_dbctx *) dbctx->priv;
	char keyurl[1024];
	int i, ofs;

	if (fingerprint->length > MAX_FINGERPRINT_LEN) {
		return 0;
	}

	ofs = snprintf(keyurl, sizeof(keyurl),
			"%s/lookup?op=get&search=0x", privctx->hkpbase);

	if ((ofs + fingerprint->length * 2 + 1)> sizeof(keyurl)) {
		return 0;
	}

	for (i = 0; i < fingerprint->length; i++) {
		ofs += sprintf(&keyurl[ofs], "%02X", fingerprint->fp[i]);
	}

	return (hkp_fetch_key_url(dbctx, keyurl, publickey, intrans));
}

/**
 *	hkp_fetch_key_id - Given a keyid fetch the key from HKP server.
 */
static int hkp_fetch_key_id(struct onak_dbctx *dbctx,
		uint64_t keyid,
		struct openpgp_publickey **publickey,
		bool intrans)
{
	struct onak_hkp_dbctx *privctx = (struct onak_hkp_dbctx *) dbctx->priv;
	char keyurl[1024];

	snprintf(keyurl, sizeof(keyurl),
			"%s/lookup?op=get&search=0x%08" PRIX64,
			privctx->hkpbase, keyid);

	return (hkp_fetch_key_url(dbctx, keyurl, publickey, intrans));
}

/**
 *	fetch_key_text - Tries to find the keys that contain the supplied text.
 *	@search: The text to search for.
 *	@publickey: A pointer to a structure to return the key in.
 *
 *	This function searches for the supplied text and returns the keys that
 *	contain it.
 *
 *	TODO: Write for flat file access. Some sort of grep?
 */
static int hkp_fetch_key_text(struct onak_dbctx *dbctx,
		const char *search,
		struct openpgp_publickey **publickey)
{
	struct onak_hkp_dbctx *privctx = (struct onak_hkp_dbctx *) dbctx->priv;
	char keyurl[1024];

	snprintf(keyurl, sizeof(keyurl),
			"%s/lookup?op=get&search=%s",
			privctx->hkpbase, search);

	return (hkp_fetch_key_url(dbctx, keyurl, publickey, false));
}

/**
 *	store_key - Takes a key and stores it.
 *	@publickey: A pointer to the public key to store.
 *	@intrans: If we're already in a transaction.
 *	@update: If true the key exists and should be updated.
 *
 */
static int hkp_store_key(struct onak_dbctx *dbctx,
		struct openpgp_publickey *publickey, bool intrans,
		bool update)
{
	struct onak_hkp_dbctx *privctx = (struct onak_hkp_dbctx *) dbctx->priv;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	char keyurl[1024];
	CURLcode res;
	struct buffer_ctx buf;
	char *addform;

	buf.offset = 0;
	buf.size = 8192;
	buf.buffer = malloc(8192);
	buf.offset = snprintf(buf.buffer, buf.size, "keytextz");

	flatten_publickey(publickey, &packets, &list_end);
	armor_openpgp_stream(buffer_putchar, &buf, packets);
	addform = curl_easy_escape(privctx->curl, buf.buffer, buf.offset);
	addform[7] = '=';

	snprintf(keyurl, sizeof(keyurl), "%s/add", privctx->hkpbase);

	curl_easy_setopt(privctx->curl, CURLOPT_URL, keyurl);
	curl_easy_setopt(privctx->curl, CURLOPT_POSTFIELDS, addform);
	curl_easy_setopt(privctx->curl, CURLOPT_WRITEFUNCTION,
			hkp_curl_recv_data);
	buf.offset = 0;
	curl_easy_setopt(privctx->curl, CURLOPT_WRITEDATA, &buf);
	res = curl_easy_perform(privctx->curl);

	if (res != 0) {
		logthing(LOGTHING_ERROR, "Couldn't send key: %s (%d)",
			curl_easy_strerror(res), res);
	}

	curl_free(addform);

	/* TODO: buf has any response text we might want to parse. */
	free(buf.buffer);
	buf.offset = buf.size = 0;
	buf.buffer = NULL;

	return (res == 0) ? 1 : 0;
}

/**
 *	delete_key - Given a keyid delete the key from storage.
 *	@fp: The fingerprint of the key to delete.
 *	@intrans: If we're already in a transaction.
 *
 *	No op for HKP.
 */
static int hkp_delete_key(struct onak_dbctx *dbctx,
		struct openpgp_fingerprint *fp, bool intrans)
{
	return -1;
}

/**
 *	iterate_keys - call a function once for each key in the db.
 *	@iterfunc: The function to call.
 *	@ctx: A context pointer
 *
 *	Not applicable for HKP backend.
 */
static int hkp_iterate_keys(struct onak_dbctx *dbctx,
		void (*iterfunc)(void *ctx, struct openpgp_publickey *key),
		void *ctx)
{
	return 0;
}

/**
 *	starttrans - Start a transaction.
 *
 *	This is just a no-op for HKP access.
 */
static bool hkp_starttrans(struct onak_dbctx *dbctx)
{
	return true;
}

/**
 *	endtrans - End a transaction.
 *
 *	This is just a no-op for HKP access.
 */
static void hkp_endtrans(struct onak_dbctx *dbctx)
{
	return;
}

/*
 * Include the basic keydb routines.
 */
#define NEED_KEYID2UID 1
#define NEED_GETKEYSIGS 1
#define NEED_UPDATEKEYS 1
#define NEED_GET 1
#include "keydb.c"

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	We cleanup CURL here.
 */
static void hkp_cleanupdb(struct onak_dbctx *dbctx)
{
	struct onak_hkp_dbctx *privctx = (struct onak_hkp_dbctx *) dbctx->priv;

	if (privctx->curl) {
		curl_easy_cleanup(privctx->curl);
		privctx->curl = NULL;
	}
	curl_global_cleanup();
	free(privctx);
	free(dbctx);
}

/**
 *	initdb - Initialize the key database.
 *
 *	We initialize CURL here.
 */
struct onak_dbctx *keydb_hkp_init(struct onak_db_config *dbcfg, bool readonly)
{
	struct onak_dbctx *dbctx;
	struct onak_hkp_dbctx *privctx;
	curl_version_info_data *curl_info;

	dbctx = malloc(sizeof(struct onak_dbctx));
	if (dbctx == NULL) {
		return NULL;
	}

	dbctx->config = dbcfg;
	dbctx->priv = privctx = malloc(sizeof(*privctx));
	dbctx->cleanupdb		= hkp_cleanupdb;
	dbctx->starttrans		= hkp_starttrans;
	dbctx->endtrans			= hkp_endtrans;
	dbctx->fetch_key		= generic_fetch_key;
	dbctx->fetch_key_fp		= hkp_fetch_key_fp;
	dbctx->fetch_key_id		= hkp_fetch_key_id;
	dbctx->fetch_key_text		= hkp_fetch_key_text;
	dbctx->store_key		= hkp_store_key;
	dbctx->update_keys		= generic_update_keys;
	dbctx->delete_key		= hkp_delete_key;
	dbctx->getkeysigs		= generic_getkeysigs;
	dbctx->cached_getkeysigs	= generic_cached_getkeysigs;
	dbctx->keyid2uid		= generic_keyid2uid;
	dbctx->iterate_keys		= hkp_iterate_keys;

	if (!hkp_parse_url(privctx, dbcfg->location)) {
		exit(EXIT_FAILURE);
	}
	logthing(LOGTHING_INFO, "Using %s as HKP forwarding URL.",
		privctx->hkpbase);
	curl_global_init(CURL_GLOBAL_DEFAULT);
	privctx->curl = curl_easy_init();
	if (privctx->curl == NULL) {
		logthing(LOGTHING_CRITICAL, "Could not initialize CURL.");
		hkp_cleanupdb(dbctx);
		dbctx = NULL;
		exit(EXIT_FAILURE);
	}
	curl_easy_setopt(privctx->curl, CURLOPT_USERAGENT,
		"onak/" ONAK_VERSION);

	if (strncmp(privctx->hkpbase, "https://", 8) == 0) {
		curl_info = curl_version_info(CURLVERSION_NOW);
		if (! (curl_info->features & CURL_VERSION_SSL)) {
			logthing(LOGTHING_CRITICAL,
				"CURL lacks SSL support; cannot use HKP url: %s",
				privctx->hkpbase);
			hkp_cleanupdb(dbctx);
			dbctx = NULL;
			exit(EXIT_FAILURE);
		}
	}

	return dbctx;
}
