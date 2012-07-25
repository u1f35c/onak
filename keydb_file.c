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
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "charfuncs.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "ll.h"
#include "log.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"

/**
 *	initdb - Initialize the key database.
 *
 *	This is just a no-op for flat file access.
 */
static void file_initdb(bool readonly)
{
}

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	This is just a no-op for flat file access.
 */
static void file_cleanupdb(void)
{
}

/**
 *	starttrans - Start a transaction.
 *
 *	This is just a no-op for flat file access.
 */
static bool file_starttrans(void)
{
	return true;
}

/**
 *	endtrans - End a transaction.
 *
 *	This is just a no-op for flat file access.
 */
static void file_endtrans(void)
{
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
static int file_fetch_key(uint64_t keyid, struct openpgp_publickey **publickey,
		bool intrans)
{
	struct openpgp_packet_list *packets = NULL;
	char keyfile[1024];
	int fd = -1;

	snprintf(keyfile, 1023, "%s/0x%" PRIX64, config.db_dir,
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
static int file_store_key(struct openpgp_publickey *publickey, bool intrans,
		bool update)
{
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct openpgp_publickey *next = NULL;
	char keyfile[1024];
	int fd = -1;
	uint64_t keyid;

	get_keyid(publickey, &keyid);
	snprintf(keyfile, 1023, "%s/0x%" PRIX64, config.db_dir,
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
 *	@keyid: The keyid to delete.
 *	@intrans: If we're already in a transaction.
 *
 *	This function deletes a public key from whatever storage mechanism we
 *	are using. Returns 0 if the key existed.
 */
static int file_delete_key(uint64_t keyid, bool intrans)
{
	char keyfile[1024];

	snprintf(keyfile, 1023, "%s/0x%" PRIX64, config.db_dir,
			keyid & 0xFFFFFFFF);

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
static int file_fetch_key_text(const char *search,
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
static int file_iterate_keys(void (*iterfunc)(void *ctx,
		struct openpgp_publickey *key),	void *ctx)
{
	int                         numkeys = 0;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_publickey   *key = NULL;
	DIR                        *dir;
	char                        keyfile[1024];
	int                         fd = -1;
	struct dirent              *curfile = NULL;

	dir = opendir(config.db_dir);

	if (dir != NULL) {
		while ((curfile = readdir(dir)) != NULL) {
			if (curfile->d_name[0] == '0' &&
					curfile->d_name[1] == 'x') {
				snprintf(keyfile, 1023, "%s/%s",
						config.db_dir,
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
#define NEED_GETFULLKEYID 1
#define NEED_UPDATEKEYS 1
#include "keydb.c"

struct dbfuncs keydb_file_funcs = {
	.initdb			= file_initdb,
	.cleanupdb		= file_cleanupdb,
	.starttrans		= file_starttrans,
	.endtrans		= file_endtrans,
	.fetch_key		= file_fetch_key,
	.fetch_key_text		= file_fetch_key_text,
	.store_key		= file_store_key,
	.update_keys		= generic_update_keys,
	.delete_key		= file_delete_key,
	.getkeysigs		= generic_getkeysigs,
	.cached_getkeysigs	= generic_cached_getkeysigs,
	.keyid2uid		= generic_keyid2uid,
	.getfullkeyid		= generic_getfullkeyid,
	.iterate_keys		= file_iterate_keys,
};
