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
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

#include "armor.h"
#include "charfuncs.h"
#include "keydb.h"
#include "keystructs.h"
#include "log.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"
#include "version.h"

static CURL *curl = NULL;

/**
 *	initdb - Initialize the key database.
 *
 *	We initialize CURL here.
 */
static void hkp_initdb(bool readonly)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();
	if (curl == NULL) {
		logthing(LOGTHING_CRITICAL, "Could not initialize CURL.");
		exit(EXIT_FAILURE);
	}
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "onak/" ONAK_VERSION);
}

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	We cleanup CURL here.
 */
static void hkp_cleanupdb(void)
{
	if (curl) {
		curl_easy_cleanup(curl);
		curl = NULL;
	}
	curl_global_cleanup();
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
static int hkp_fetch_key(uint64_t keyid, struct openpgp_publickey **publickey,
		bool intrans)
{
	struct openpgp_packet_list *packets = NULL;
	char keyurl[1024];
	CURLcode res;
	struct buffer_ctx buf;

	buf.offset = 0;
	buf.size = 8192;
	buf.buffer = malloc(8192);

	snprintf(keyurl, sizeof(keyurl),
			"http://%s:11371/pks/lookup?op=get&search=0x%08" PRIX64,
			config.db_dir, keyid);

	curl_easy_setopt(curl, CURLOPT_URL, keyurl);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			hkp_curl_recv_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	res = curl_easy_perform(curl);

	if (res == 0) {
		buf.offset = 0;
		dearmor_openpgp_stream(buffer_fetchchar, &buf, &packets);
		parse_keys(packets, publickey);
		free_packet_list(packets);
		packets = NULL;
	} else {
		logthing(LOGTHING_ERROR, "Couldn't find key: %s (%d)",
			curl_easy_strerror(res), res);
	}

	free(buf.buffer);
	buf.offset = buf.size = 0;
	buf.buffer = NULL;

	return (res == 0) ? 1 : 0;
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
static int hkp_fetch_key_text(const char *search,
		struct openpgp_publickey **publickey)
{
	struct openpgp_packet_list *packets = NULL;
	char keyurl[1024];
	CURLcode res;
	struct buffer_ctx buf;
	int count = 0;

	buf.offset = 0;
	buf.size = 8192;
	buf.buffer = malloc(8192);

	snprintf(keyurl, sizeof(keyurl),
			"http://%s:11371/pks/lookup?op=get&search=%s",
			config.db_dir, search);

	curl_easy_setopt(curl, CURLOPT_URL, keyurl);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			hkp_curl_recv_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	res = curl_easy_perform(curl);

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
 *	store_key - Takes a key and stores it.
 *	@publickey: A pointer to the public key to store.
 *	@intrans: If we're already in a transaction.
 *	@update: If true the key exists and should be updated.
 *
 */
static int hkp_store_key(struct openpgp_publickey *publickey, bool intrans,
		bool update)
{
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
	addform = curl_easy_escape(curl, buf.buffer, buf.offset);
	addform[7] = '=';

	snprintf(keyurl, sizeof(keyurl),
			"http://%s:11371/pks/add",
			config.db_dir);

	curl_easy_setopt(curl, CURLOPT_URL, keyurl);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, addform);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			hkp_curl_recv_data);
	buf.offset = 0;
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	res = curl_easy_perform(curl);

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
 *	@keyid: The keyid to delete.
 *	@intrans: If we're already in a transaction.
 *
 *	No op for HKP.
 */
static int hkp_delete_key(uint64_t keyid, bool intrans)
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
static int hkp_iterate_keys(void (*iterfunc)(void *ctx,
		struct openpgp_publickey *key),	void *ctx)
{
	return 0;
}

/**
 *	starttrans - Start a transaction.
 *
 *	This is just a no-op for HKP access.
 */
static bool hkp_starttrans(void)
{
	return true;
}

/**
 *	endtrans - End a transaction.
 *
 *	This is just a no-op for HKP access.
 */
static void hkp_endtrans(void)
{
	return;
}

/*
 * Include the basic keydb routines.
 */
#define NEED_KEYID2UID 1
#define NEED_GETKEYSIGS 1
#define NEED_GETFULLKEYID 1
#define NEED_UPDATEKEYS 1
#include "keydb.c"

struct dbfuncs keydb_hkp_funcs = {
	.initdb			= hkp_initdb,
	.cleanupdb		= hkp_cleanupdb,
	.starttrans		= hkp_starttrans,
	.endtrans		= hkp_endtrans,
	.fetch_key		= hkp_fetch_key,
	.fetch_key_text		= hkp_fetch_key_text,
	.store_key		= hkp_store_key,
	.update_keys		= generic_update_keys,
	.delete_key		= hkp_delete_key,
	.getkeysigs		= generic_getkeysigs,
	.cached_getkeysigs	= generic_cached_getkeysigs,
	.keyid2uid		= generic_keyid2uid,
	.getfullkeyid		= generic_getfullkeyid,
	.iterate_keys		= hkp_iterate_keys,
};
