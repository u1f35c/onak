/*
 * keydb.c - Routines to store and fetch keys.
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

#include <sys/types.h>
#include <sys/uio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "charfuncs.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "log.h"
#include "mem.h"
#include "onak.h"
#include "onak-conf.h"
#include "parsekey.h"

/**
 *	starttrans - Start a transaction.
 *
 *	This is just a no-op for flat file access.
 */
static bool file_starttrans(struct onak_dbctx *dbctx)
{
	return true;
}

/**
 *	endtrans - End a transaction.
 *
 *	This is just a no-op for flat file access.
 */
static void file_endtrans(struct onak_dbctx *dbctx)
{
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
static int file_fetch_key_id(struct onak_dbctx *dbctx,
		uint64_t keyid,
		struct openpgp_publickey **publickey,
		bool intrans)
{
	char *db_dir = (char *) dbctx->priv;
	struct openpgp_packet_list *packets = NULL;
	char keyfile[1024];
	int fd = -1;

	snprintf(keyfile, 1023, "%s/0x%" PRIX64, db_dir,
			keyid & 0xFFFFFFFF);
	fd = open(keyfile, O_RDONLY); // | O_SHLOCK);

	if (fd > -1) {
		read_openpgp_stream(file_fetchchar, &fd, &packets, 0);
		parse_keys(packets, publickey);
		free_packet_list(packets);
		packets = NULL;
		close(fd);
	}

	return (fd > -1);
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
 *	the file.
 */
static int file_store_key(struct onak_dbctx *dbctx,
		struct openpgp_publickey *publickey, bool intrans,
		bool update)
{
	char *db_dir = (char *) dbctx->priv;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct openpgp_publickey *next = NULL;
	char keyfile[1024];
	int fd = -1;
	uint64_t keyid;

	if (get_keyid(publickey, &keyid) != ONAK_E_OK) {
		logthing(LOGTHING_ERROR, "Couldn't find key ID for key.");
		return 0;
	}
	snprintf(keyfile, 1023, "%s/0x%" PRIX64, db_dir,
			keyid & 0xFFFFFFFF);
	fd = open(keyfile, O_WRONLY | O_CREAT, 0664); // | O_EXLOCK);

	if (fd > -1) {
		next = publickey -> next;
		publickey -> next = NULL;
		flatten_publickey(publickey, &packets, &list_end);
		publickey -> next = next;
		
		write_openpgp_stream(file_putchar, &fd, packets);
		close(fd);
		free_packet_list(packets);
		packets = NULL;
	}

	return (fd > -1);
}

/**
 *	delete_key - Given a keyid delete the key from storage.
 *	@fp: The fingerprint of the key to delete.
 *	@intrans: If we're already in a transaction.
 *
 *	This function deletes a public key from whatever storage mechanism we
 *	are using. Returns 0 if the key existed.
 */
static int file_delete_key(struct onak_dbctx *dbctx,
		struct openpgp_fingerprint *fp, bool intrans)
{
	char *db_dir = (char *) dbctx->priv;
	char keyfile[1024];

	snprintf(keyfile, 1023, "%s/0x%" PRIX64, db_dir,
			fingerprint2keyid(fp) & 0xFFFFFFFF);

	return unlink(keyfile);
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
static int file_fetch_key_text(struct onak_dbctx *dbctx,
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
static int file_iterate_keys(struct onak_dbctx *dbctx,
		void (*iterfunc)(void *ctx, struct openpgp_publickey *key),
		void *ctx)
{
	char *db_dir = (char *) dbctx->priv;
	int                         numkeys = 0;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_publickey   *key = NULL;
	DIR                        *dir;
	char                        keyfile[1024];
	int                         fd = -1;
	struct dirent              *curfile = NULL;

	dir = opendir(db_dir);

	if (dir != NULL) {
		while ((curfile = readdir(dir)) != NULL) {
			if (curfile->d_name[0] == '0' &&
					curfile->d_name[1] == 'x') {
				snprintf(keyfile, 1023, "%s/%s",
						db_dir,
						curfile->d_name);
				fd = open(keyfile, O_RDONLY);

				if (fd > -1) {
					read_openpgp_stream(file_fetchchar,
							&fd,
							&packets,
							0);
					parse_keys(packets, &key);

					iterfunc(ctx, key);

					free_publickey(key);
					key = NULL;
					free_packet_list(packets);
					packets = NULL;
					close(fd);
				}
				numkeys++;
			}
		}
		
		closedir(dir);
		dir = NULL;
	}

	return numkeys;
}

/*
 * Include the basic keydb routines.
 */
#define NEED_KEYID2UID 1
#define NEED_GETKEYSIGS 1
#define NEED_UPDATEKEYS 1
#define NEED_GET_FP 1
#include "keydb.c"

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	This is just a no-op for flat file access.
 */
static void file_cleanupdb(struct onak_dbctx *dbctx)
{
	if (dbctx->priv != NULL) {
		free(dbctx->priv);
		dbctx->priv = NULL;
	}

	if (dbctx != NULL) {
		free(dbctx);
	}
}

/**
 *	initdb - Initialize the key database.
 *
 *	This is just a no-op for flat file access.
 */
struct onak_dbctx *keydb_file_init(struct onak_db_config *dbcfg, bool readonly)
{
	struct onak_dbctx *dbctx;

	dbctx = malloc(sizeof(struct onak_dbctx));
	if (dbctx == NULL) {
		return NULL;
	}

	dbctx->config = dbcfg;
	dbctx->priv = strdup(dbcfg->location);

	dbctx->cleanupdb		= file_cleanupdb;
	dbctx->starttrans		= file_starttrans;
	dbctx->endtrans			= file_endtrans;
	/* Our fetch fp doesn't look at subkeys */
	dbctx->fetch_key		= generic_fetch_key_fp;
	dbctx->fetch_key_fp		= generic_fetch_key_fp;
	dbctx->fetch_key_id		= file_fetch_key_id;
	dbctx->fetch_key_text		= file_fetch_key_text;
	dbctx->store_key		= file_store_key;
	dbctx->update_keys		= generic_update_keys;
	dbctx->delete_key		= file_delete_key;
	dbctx->getkeysigs		= generic_getkeysigs;
	dbctx->cached_getkeysigs	= generic_cached_getkeysigs;
	dbctx->keyid2uid		= generic_keyid2uid;
	dbctx->iterate_keys		= file_iterate_keys;

	return dbctx;
}
