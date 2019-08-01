/*
 * keydb_keyring.c - Routines to fetch keys from a PGP keyring file.
 *
 * Copyright 2019 Jonathan McDowell <noodles@earth.li>
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

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "charfuncs.h"
#include "keyarray.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "log.h"
#include "mem.h"
#include "onak.h"
#include "onak-conf.h"
#include "parsekey.h"

struct onak_keyring_dbctx {
	uint8_t *file;
	size_t   length;
	unsigned int space;
	unsigned int count;
	struct {
		struct openpgp_fingerprint fp;
		uint8_t *start;
		size_t len;
	} *keys;
};

/**
 *	starttrans - Start a transaction.
 *
 *	This is just a no-op for keyring file access.
 */
static bool keyring_starttrans(struct onak_dbctx *dbctx)
{
	return true;
}

/**
 *	endtrans - End a transaction.
 *
 *	This is just a no-op for keyring file access.
 */
static void keyring_endtrans(struct onak_dbctx *dbctx)
{
	return;
}

/**
 * keyring_fetch_key - fetch a key given its index
 */
static int keyring_fetch_key(struct onak_keyring_dbctx *privctx,
		unsigned int index,
		struct openpgp_publickey **publickey)
{
	struct openpgp_packet_list *packets = NULL;
	struct buffer_ctx buf;

	if (index > privctx->count)
		return 0;

	buf.buffer = privctx->keys[index].start;
	buf.size = privctx->keys[index].len;
	buf.offset = 0;

	read_openpgp_stream(buffer_fetchchar, &buf, &packets, 0);
	parse_keys(packets, publickey);
	free_packet_list(packets);
	packets = NULL;

	return 1;
}

static int keyring_fetch_key_fp(struct onak_dbctx *dbctx,
			struct openpgp_fingerprint *fingerprint,
			struct openpgp_publickey **publickey,
			bool intrans)
{
	struct onak_keyring_dbctx *privctx =
		(struct onak_keyring_dbctx *) dbctx->priv;
	int i;

	for (i = 0; i < privctx->count; i++) {
		if (fingerprint_cmp(fingerprint, &privctx->keys[i].fp) == 0)
			break;
	}

	if (i < privctx->count) {
		return keyring_fetch_key(privctx, i, publickey);
	}

	return 0;
}

/**
 *	fetch_key_id - Given a keyid fetch the key from storage.
 *	@keyid: The keyid to fetch.
 *	@publickey: A pointer to a structure to return the key in.
 *	@intrans: If we're already in a transaction.
 */
static int keyring_fetch_key_id(struct onak_dbctx *dbctx,
		uint64_t keyid,
		struct openpgp_publickey **publickey,
		bool intrans)
{
	struct onak_keyring_dbctx *privctx =
		(struct onak_keyring_dbctx *) dbctx->priv;
	int count, i;

	count = 0;
	for (i = 0; i < privctx->count; i++) {
		if (fingerprint2keyid(&privctx->keys[i].fp) == keyid) {
			if (keyring_fetch_key(privctx, i, publickey))
				count++;
		}
	}

	return count;
}

/**
 *	store_key - Takes a key and stores it.
 *	@publickey: A pointer to the public key to store.
 *	@intrans: If we're already in a transaction.
 *	@update: If true the key exists and should be updated.
 *
 *	We don't support storing keys into a keyring file.
 */
static int keyring_store_key(struct onak_dbctx *dbctx,
		struct openpgp_publickey *publickey, bool intrans,
		bool update)
{
	return 0;
}

/**
 *	delete_key - Given a keyid delete the key from storage.
 *	@fp: The fingerprint of the key to delete.
 *	@intrans: If we're already in a transaction.
 *
 *	We don't support removing keys from a keyring file.
 */
static int keyring_delete_key(struct onak_dbctx *dbctx,
		struct openpgp_fingerprint *fp, bool intrans)
{
	return 1;
}

/**
 *	fetch_key_text - Trys to find the keys that contain the supplied text.
 *	@search: The text to search for.
 *	@publickey: A pointer to a structure to return the key in.
 *
 *	This function searches for the supplied text and returns the keys that
 *	contain it.
 *
 *	TODO: Write for flat file access. Some sort of grep?
 */
static int keyring_fetch_key_text(struct onak_dbctx *dbctx,
		const char *search,
		struct openpgp_publickey **publickey)
{
	return 0;
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
static int keyring_iterate_keys(struct onak_dbctx *dbctx,
		void (*iterfunc)(void *ctx, struct openpgp_publickey *key),
		void *ctx)
{
	struct onak_keyring_dbctx *privctx =
		(struct onak_keyring_dbctx *) dbctx->priv;
	struct openpgp_publickey  *key = NULL;
	int count, i;

	count = 0;
	for (i = 0; i < privctx->count; i++) {
		if (keyring_fetch_key(privctx, i, &key)) {
			iterfunc(ctx, key);
			free_publickey(key);
			key = NULL;
		}
	}

	return count;
}

static int keyring_update_keys(struct onak_dbctx *dbctx,
                struct openpgp_publickey **keys, bool sendsync)
{
	return 0;
}

/*
 * Include the basic keydb routines.
 */
#define NEED_KEYID2UID 1
#define NEED_GETKEYSIGS 1
#define NEED_GETFULLKEYID 1
#define NEED_GET_FP 1
#include "keydb.c"

static int keyring_parse_keys(struct onak_keyring_dbctx *privctx)
{
	size_t len, pos, start, totlen;
	struct openpgp_publickey *key;
	uint8_t tag;

	if (privctx == NULL) {
		return 0;
	}

	if (privctx->file == NULL) {
		return 0;
	}

	/*
	 * Walk the keyring file, noting the start of each public key and the
	 * total length of packets associated with it.
	 */
	len = pos = start = totlen = 0;
	while (((privctx->length - pos) > 5) && (privctx->file[pos] & 0x80)) {
		if (privctx->file[pos] & 0x40) {
			tag = privctx->file[pos] & 0x3F;
			len = privctx->file[pos + 1];
			if (len > 191 && len < 224) {
				len -= 192;
				len <<= 8;
				len += privctx->file[pos + 2];
				len += 192;
				len += 1; /* Header */
			} else if (len > 223 & len < 255) {
				// Unsupported
			} else if (len == 255) {
				len = privctx->file[pos + 2];
				len <<= 8;
				len += privctx->file[pos + 3];
				len <<= 8;
				len += privctx->file[pos + 4];
				len <<= 8;
				len += privctx->file[pos + 5];
				len += 4; /* Header */
			}
			len += 2; /* Header */
		} else {
			tag = (privctx->file[pos] & 0x3C) >> 2;
			switch (privctx->file[pos] & 3) {
			case 0:
				len = privctx->file[pos + 1];
				len += 2; /* Header */
				break;
			case 1:
				len = privctx->file[pos + 1];
				len <<= 8;
				len += privctx->file[pos + 2];
				len += 3; /* Header */
				break;
			case 2:
				len = privctx->file[pos + 1];
				len <<= 8;
				len += privctx->file[pos + 2];
				len <<= 8;
				len += privctx->file[pos + 3];
				len <<= 8;
				len += privctx->file[pos + 4];
				len += 5; /* Header */
				break;
			case 3:
				// Unsupported
				break;
			}
		}
		if (tag == OPENPGP_PACKET_PUBLICKEY) {
			if (totlen > 0) {
				/* Expand the array of keys if necessary */
				if (privctx->count == privctx->space) {
					privctx->space *= 2;
					privctx->keys = realloc(privctx->keys,
						privctx->space *
						sizeof(*privctx->keys));
				}

				/* TODO: Sort by fingerprint? */
				privctx->keys[privctx->count].start =
					&privctx->file[start];
				privctx->keys[privctx->count].len = totlen;
				privctx->count++;

				/*
				 * We need to fetch the key to calculate the
				 * fingerprint.
				 */
				keyring_fetch_key(privctx, privctx->count - 1,
						&key);
				get_fingerprint(key->publickey,
					&privctx->keys[privctx->count - 1].fp);
				free_publickey(key);
				key = NULL;
			}
			start = pos;
			totlen = 0;
		}
		totlen += len;
		pos += len;
	}

	return privctx->count;
}

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	This is just a no-op for flat file access.
 */
static void keyring_cleanupdb(struct onak_dbctx *dbctx)
{
	struct onak_keyring_dbctx *privctx =
		(struct onak_keyring_dbctx *) dbctx->priv;

	if (dbctx->priv != NULL) {
		if (privctx->file != NULL) {
			munmap(privctx->file, privctx->length);
		}
		free(privctx->keys);
		free(dbctx->priv);
		dbctx->priv = NULL;
	}

	if (dbctx != NULL) {
		free(dbctx);
	}
};

/**
 *	initdb - Initialize the key database.
 *
 *	This is just a no-op for flat file access.
 */
struct onak_dbctx *keydb_keyring_init(struct onak_db_config *dbcfg,
		bool readonly)
{
	struct onak_keyring_dbctx *privctx;
	struct onak_dbctx *dbctx;
	struct stat sb;
	int fd;

	dbctx = malloc(sizeof(struct onak_dbctx));
	if (dbctx == NULL) {
		return NULL;
	}
	dbctx->config = dbcfg;
	dbctx->priv = privctx = calloc(1, sizeof(*privctx));
	if (privctx == NULL) {
		free(dbctx);
		return NULL;
	}
	privctx->space = 16;
	privctx->keys = calloc(privctx->space, sizeof(*privctx->keys));

	fd = open(dbcfg->location, O_RDONLY);
	if (fd < 0) {
		logthing(LOGTHING_CRITICAL,
				"Couldn't open keyring file %s: %s (%d)",
				dbcfg->location,
				strerror(errno),
				errno);
		keyring_cleanupdb(dbctx);
		return NULL;
	}
	if (fstat(fd, &sb) < 0) {
		logthing(LOGTHING_CRITICAL,
				"Couldn't stat keyring file %s: %s (%d)",
				dbcfg->location,
				strerror(errno),
				errno);
		close(fd);
		keyring_cleanupdb(dbctx);
		return NULL;
	}
	privctx->file = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (privctx->file == MAP_FAILED) {
		logthing(LOGTHING_CRITICAL,
				"Couldn't mmap keyring file %s: %s (%d)",
				dbcfg->location,
				strerror(errno),
				errno);
		privctx->file = NULL;
		close(fd);
		keyring_cleanupdb(dbctx);
		return NULL;
	}
	privctx->length = sb.st_size;
	close(fd);

	if (keyring_parse_keys(privctx) == 0) {
		logthing(LOGTHING_CRITICAL,
				"Failed to load any keys from keyring file %s",
				dbcfg->location);
		keyring_cleanupdb(dbctx);
		return NULL;
	}

	dbctx->cleanupdb		= keyring_cleanupdb;
	dbctx->starttrans		= keyring_starttrans;
	dbctx->endtrans			= keyring_endtrans;
	dbctx->fetch_key_id		= keyring_fetch_key_id;
	dbctx->fetch_key_fp		= keyring_fetch_key_fp;
	dbctx->fetch_key_text		= keyring_fetch_key_text;
	dbctx->store_key		= keyring_store_key;
	dbctx->update_keys		= keyring_update_keys;
	dbctx->delete_key		= keyring_delete_key;
	dbctx->getkeysigs		= generic_getkeysigs;
	dbctx->cached_getkeysigs	= generic_cached_getkeysigs;
	dbctx->keyid2uid		= generic_keyid2uid;
	dbctx->getfullkeyid		= generic_getfullkeyid;
	dbctx->iterate_keys		= keyring_iterate_keys;

	return dbctx;
}
