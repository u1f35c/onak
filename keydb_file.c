/*
 * keydb.c - Routines to store and fetch keys.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 *
 * $Id: keydb_file.c,v 1.11 2004/03/23 12:33:46 noodles Exp $
 */

#include <sys/types.h>
#include <sys/uio.h>
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
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"

/**
 *	initdb - Initialize the key database.
 *
 *	This is just a no-op for flat file access.
 */
void initdb(bool readonly)
{
}

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	This is just a no-op for flat file access.
 */
void cleanupdb(void)
{
}

/**
 *	starttrans - Start a transaction.
 *
 *	This is just a no-op for flat file access.
 */
bool starttrans(void)
{
	return true;
}

/**
 *	endtrans - End a transaction.
 *
 *	This is just a no-op for flat file access.
 */
void endtrans(void)
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
int fetch_key(uint64_t keyid, struct openpgp_publickey **publickey,
		bool intrans)
{
	struct openpgp_packet_list *packets = NULL;
	char keyfile[1024];
	int fd = -1;

	snprintf(keyfile, 1023, "%s/0x%llX", config.db_dir,
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
int store_key(struct openpgp_publickey *publickey, bool intrans, bool update)
{
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct openpgp_publickey *next = NULL;
	char keyfile[1024];
	int fd = -1;

	snprintf(keyfile, 1023, "%s/0x%llX", config.db_dir,
			get_keyid(publickey) & 0xFFFFFFFF);
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
int delete_key(uint64_t keyid, bool intrans)
{
	char keyfile[1024];

	snprintf(keyfile, 1023, "%s/0x%llX", config.db_dir,
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
int fetch_key_text(const char *search, struct openpgp_publickey **publickey)
{
	return 0;
}

/**
 *	dumpdb - dump the key database
 *	@filenamebase: The base filename to use for the dump.
 *
 *	Dumps the database into one or more files, which contain pure OpenPGP
 *	that can be reimported into onak or gpg. filenamebase provides a base
 *	file name for the dump; several files may be created, all of which will
 *	begin with this string and then have a unique number and a .pgp
 *	extension.
 *          */
int dumpdb(char *filenamebase)
{
	return 0;
}

/*
 * Include the basic keydb routines.
 */
#define NEED_KEYID2UID 1
#define NEED_GETKEYSIGS 1
#define NEED_GETFULLKEYID 1
#include "keydb.c"
