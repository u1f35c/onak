/*
 * keydb.c - Routines to store and fetch keys.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "ll.h"
#include "mem.h"
#include "parsekey.h"

#define DBDIR "/home/noodles/onak-0.0.1/db"

/**
 *	keydb_fetchchar - Fetches a char from a file.
 */
static int keydb_fetchchar(void *fd, size_t count, unsigned char *c)
{
	return !(read( *(int *) fd, c, count));
}

/**
 *	keydb_putchar - Puts a char to a file.
 */
static int keydb_putchar(void *fd, unsigned char c)
{
	return !(write( *(int *) fd, &c, sizeof(c)));
}

/**
 *	initdb - Initialize the key database.
 *
 *	This is just a no-op for flat file access.
 */
void initdb(void)
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
 *	fetch_key - Given a keyid fetch the key from storage.
 *	@keyid: The keyid to fetch.
 *	@publickey: A pointer to a structure to return the key in.
 *
 *	We use the hex representation of the keyid as the filename to fetch the
 *	key from. The key is stored in the file as a binary OpenPGP stream of
 *	packets, so we can just use read_openpgp_stream() to read the packets
 *	in and then parse_keys() to parse the packets into a publickey
 *	structure.
 */
int fetch_key(uint64_t keyid, struct openpgp_publickey **publickey)
{
	struct openpgp_packet_list *packets = NULL;
	char keyfile[1024];
	int fd = -1;

	snprintf(keyfile, 1023, "%s/0x%llX", DBDIR, keyid & 0xFFFFFFFF);
	fd = open(keyfile, O_RDONLY); // | O_SHLOCK);

	if (fd > -1) {
		read_openpgp_stream(keydb_fetchchar, &fd, &packets);
		parse_keys(packets, publickey);
		close(fd);
	}

	return (fd > -1);
}

/**
 *	store_key - Takes a key and stores it.
 *	@publickey: A pointer to the public key to store.
 *
 *	Again we just use the hex representation of the keyid as the filename
 *	to store the key to. We flatten the public key to a list of OpenPGP
 *	packets and then use write_openpgp_stream() to write the stream out to
 *	the file.
 */
int store_key(struct openpgp_publickey *publickey)
{
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct openpgp_publickey *next = NULL;
	char keyfile[1024];
	int fd = -1;

	snprintf(keyfile, 1023, "%s/0x%llX", DBDIR,
			get_keyid(publickey) & 0xFFFFFFFF);
	fd = open(keyfile, O_WRONLY | O_CREAT, 0664); // | O_EXLOCK);

	if (fd > -1) {
		next = publickey -> next;
		publickey -> next = NULL;
		flatten_publickey(publickey, &packets, &list_end);
		publickey -> next = next;
		
		write_openpgp_stream(keydb_putchar, &fd, packets);
		close(fd);
	}

	return (fd > -1);
}

/**
 *	delete_key - Given a keyid delete the key from storage.
 *	@keyid: The keyid to delete.
 *
 *	This function deletes a public key from whatever storage mechanism we
 *	are using. Returns 0 if the key existed.
 */
int delete_key(uint64_t keyid)
{
	char keyfile[1024];

	snprintf(keyfile, 1023, "%s/0x%llX", DBDIR,
			keyid & 0xFFFFFFFF);

	return unlink(keyfile);
}

/*
 * Include the basic keydb routines.
 */
#include "keydb.c"
