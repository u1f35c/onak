/*
 * keydb_keyd.c - Routines to talk to keyd backend.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2004 Project Purple
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "charfuncs.h"
#include "keyd.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "log.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"

/**
 *	keyd_fd - our file descriptor for the socket connection to keyd.
 */
static int keyd_fd = -1;

/**
 *	initdb - Initialize the key database.
 *	@readonly: If we'll only be reading the DB, not writing to it.
 *
 *	This function should be called before any of the other functions in
 *	this file are called in order to allow the DB to be initialized ready
 *	for access.
 */
void initdb(bool readonly)
{
	struct sockaddr_un sock;
	int		   cmd = KEYD_CMD_UNKNOWN;
	int		   reply = KEYD_REPLY_UNKNOWN_CMD;
	ssize_t		   count;

	keyd_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (keyd_fd < 0) {
		logthing(LOGTHING_CRITICAL,
				"Couldn't open socket: %s (%d)",
				strerror(errno),
				errno);
		exit(EXIT_FAILURE);
	}

	sock.sun_family = AF_UNIX;
	snprintf(sock.sun_path, sizeof(sock.sun_path) - 1, "%s/%s",
			config.db_dir,
			KEYD_SOCKET);
	if (connect(keyd_fd, (struct sockaddr *) &sock, sizeof(sock)) < 0) {
		logthing(LOGTHING_CRITICAL,
				"Couldn't connect to socket %s: %s (%d)",
				sock.sun_path,
				strerror(errno),
				errno);
		exit(EXIT_FAILURE);
	}

	cmd = KEYD_CMD_VERSION;
	if (write(keyd_fd, &cmd, sizeof(cmd)) != sizeof(cmd)) {
		logthing(LOGTHING_CRITICAL,
				"Couldn't write version cmd: %s (%d)",
				strerror(errno),
				errno);
	} else {
		count = read(keyd_fd, &reply, sizeof(reply));
		if (count == sizeof(reply)) {
			if (reply == KEYD_REPLY_OK) {
				count = read(keyd_fd, &reply, sizeof(reply));
				logthing(LOGTHING_DEBUG,
						"keyd protocol version %d",
						reply);
				if (reply != keyd_version) {
					logthing(LOGTHING_CRITICAL,
						"Error! keyd protocol version "
						"mismatch. (us = %d, it = %d)",
						keyd_version, reply);
				}
			}
		}
	}

	return;
}

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	This function should be called upon program exit to allow the DB to
 *	cleanup after itself.
 */
void cleanupdb(void)
{
	if (shutdown(keyd_fd, SHUT_RDWR) < 0) {
		logthing(LOGTHING_NOTICE, "Error shutting down socket: %d",
				errno);
	}
	keyd_fd = -1;

	return;
}


/**
 *	starttrans - Start a transaction.
 *
 *	Start a transaction. Intended to be used if we're about to perform many
 *	operations on the database to help speed it all up, or if we want
 *	something to only succeed if all relevant operations are successful.
 */
bool starttrans(void)
{
	return true;
}

/**
 *	endtrans - End a transaction.
 *
 *	Ends a transaction.
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
 *	This function returns a public key from whatever storage mechanism we
 *	are using.
 *
 *      TODO: What about keyid collisions? Should we use fingerprint instead?
 */
int fetch_key(uint64_t keyid, struct openpgp_publickey **publickey,
		bool intrans)
{
	struct buffer_ctx           keybuf;
	struct openpgp_packet_list *packets = NULL;
	int                         cmd = KEYD_CMD_GET;
	ssize_t                     bytes = 0;
	ssize_t                     count = 0;

	write(keyd_fd, &cmd, sizeof(cmd));
	read(keyd_fd, &cmd, sizeof(cmd));
	if (cmd == KEYD_REPLY_OK) {
		write(keyd_fd, &keyid, sizeof(keyid));
		keybuf.offset = 0;
		read(keyd_fd, &keybuf.size, sizeof(keybuf.size));
		if (keybuf.size > 0) {
			keybuf.buffer = malloc(keybuf.size);
			bytes = count = 0;
			logthing(LOGTHING_TRACE,
					"Getting %d bytes of key data.",
					keybuf.size);
			while (bytes >= 0 && count < keybuf.size) {
				bytes = read(keyd_fd, &keybuf.buffer[count],
						keybuf.size - count);
				logthing(LOGTHING_TRACE,
						"Read %d bytes.", bytes);
				count += bytes;
			}
			read_openpgp_stream(buffer_fetchchar, &keybuf,
					&packets, 0);
			parse_keys(packets, publickey);
			free_packet_list(packets);
			packets = NULL;
			free(keybuf.buffer);
			keybuf.buffer = NULL;
			keybuf.size = 0;
		}
	}
	
	return (count > 0) ? 1 : 0;
}

/**
 *	store_key - Takes a key and stores it.
 *	@publickey: A pointer to the public key to store.
 *	@intrans: If we're already in a transaction.
 *	@update: If true the key exists and should be updated.
 *
 *	This function stores a public key in whatever storage mechanism we are
 *	using. intrans indicates if we're already in a transaction so don't
 *	need to start one. update indicates if the key already exists and is
 *	just being updated.
 *
 *	TODO: Do we store multiple keys of the same id? Or only one and replace
 *	it?
 */
int store_key(struct openpgp_publickey *publickey, bool intrans, bool update)
{
	struct buffer_ctx           keybuf;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct openpgp_publickey   *next = NULL;
	int                         cmd = KEYD_CMD_STORE;
	uint64_t                    keyid;

	keyid = get_keyid(publickey);
	
	if (update) {
		delete_key(keyid, false);
	}

	write(keyd_fd, &cmd, sizeof(cmd));
	read(keyd_fd, &cmd, sizeof(cmd));
	if (cmd == KEYD_REPLY_OK) {
		keybuf.offset = 0;
		keybuf.size = 8192;
		keybuf.buffer = malloc(keybuf.size);

		next = publickey->next;
		publickey->next = NULL;
		flatten_publickey(publickey,
				&packets,
				&list_end);
		publickey->next = next;

		write_openpgp_stream(buffer_putchar, &keybuf, packets);
		logthing(LOGTHING_TRACE, "Sending %d bytes.", keybuf.offset);
		write(keyd_fd, &keybuf.offset, sizeof(keybuf.offset));
		write(keyd_fd, keybuf.buffer, keybuf.offset);

		free_packet_list(packets);
		packets = list_end = NULL;
		free(keybuf.buffer);
		keybuf.buffer = NULL;
		keybuf.size = keybuf.offset = 0;
	}
	
	return 0;
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
	int cmd = KEYD_CMD_DELETE;

	write(keyd_fd, &cmd, sizeof(cmd));
	read(keyd_fd, &cmd, sizeof(cmd));
	if (cmd == KEYD_REPLY_OK) {
		write(keyd_fd, &keyid, sizeof(keyid));
	}
	
	return 0;
}

/**
 *	fetch_key_text - Trys to find the keys that contain the supplied text.
 *	@search: The text to search for.
 *	@publickey: A pointer to a structure to return the key in.
 *
 *	This function searches for the supplied text and returns the keys that
 *	contain it.
 */
int fetch_key_text(const char *search, struct openpgp_publickey **publickey)
{
	struct buffer_ctx           keybuf;
	struct openpgp_packet_list *packets = NULL;
	int                         cmd = KEYD_CMD_GETTEXT;
	ssize_t                     bytes = 0;
	ssize_t                     count = 0;

	write(keyd_fd, &cmd, sizeof(cmd));
	read(keyd_fd, &cmd, sizeof(cmd));
	if (cmd == KEYD_REPLY_OK) {
		bytes = strlen(search);
		write(keyd_fd, &bytes, sizeof(bytes));
		write(keyd_fd, search, bytes);
		keybuf.offset = 0;
		read(keyd_fd, &keybuf.size, sizeof(keybuf.size));
		if (keybuf.size > 0) {
			keybuf.buffer = malloc(keybuf.size);
			bytes = count = 0;
			logthing(LOGTHING_TRACE,
					"Getting %d bytes of key data.",
					keybuf.size);
			while (bytes >= 0 && count < keybuf.size) {
				bytes = read(keyd_fd, &keybuf.buffer[count],
						keybuf.size - count);
				logthing(LOGTHING_TRACE,
						"Read %d bytes.", bytes);
				count += bytes;
			}
			read_openpgp_stream(buffer_fetchchar, &keybuf,
					&packets, 0);
			parse_keys(packets, publickey);
			free_packet_list(packets);
			packets = NULL;
			free(keybuf.buffer);
			keybuf.buffer = NULL;
			keybuf.size = 0;
		}
	}
	
	return (count > 0) ? 1 : 0;

	return 0;
}

/**
 *	getfullkeyid - Maps a 32bit key id to a 64bit one.
 *	@keyid: The 32bit keyid.
 *
 *	This function maps a 32bit key id to the full 64bit one. It returns the
 *	full keyid. If the key isn't found a keyid of 0 is returned.
 */
uint64_t getfullkeyid(uint64_t keyid)
{
	int cmd = KEYD_CMD_GETFULLKEYID;

	write(keyd_fd, &cmd, sizeof(cmd));
	read(keyd_fd, &cmd, sizeof(cmd));
	if (cmd == KEYD_REPLY_OK) {
		write(keyd_fd, &keyid, sizeof(keyid));
		read(keyd_fd, &keyid, sizeof(keyid));
	}

	return keyid;
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
 */
int dumpdb(char *filenamebase)
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
int iterate_keys(void (*iterfunc)(void *ctx, struct openpgp_publickey *key),
		void *ctx)
{
	struct buffer_ctx           keybuf;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_publickey   *key = NULL;
	int                         cmd = KEYD_CMD_KEYITER;
	ssize_t                     bytes = 0;
	ssize_t                     count = 0;
	int                         numkeys = 0;

	write(keyd_fd, &cmd, sizeof(cmd));
	read(keyd_fd, &cmd, sizeof(cmd));
	if (cmd == KEYD_REPLY_OK) {
		keybuf.offset = 0;
		read(keyd_fd, &keybuf.size, sizeof(keybuf.size));
		while (keybuf.size > 0) {
			keybuf.buffer = malloc(keybuf.size);
			bytes = count = 0;
			logthing(LOGTHING_TRACE,
					"Getting %d bytes of key data.",
					keybuf.size);
			while (bytes >= 0 && count < keybuf.size) {
				bytes = read(keyd_fd, &keybuf.buffer[count],
						keybuf.size - count);
				logthing(LOGTHING_TRACE,
						"Read %d bytes.", bytes);
				count += bytes;
			}
			read_openpgp_stream(buffer_fetchchar, &keybuf,
					&packets, 0);
			parse_keys(packets, &key);

			if (iterfunc != NULL && key != NULL) {
				iterfunc(ctx, key);
			}

			free_publickey(key);
			key = NULL;
			free_packet_list(packets);
			packets = NULL;
			free(keybuf.buffer);
			keybuf.buffer = NULL;
			keybuf.size = keybuf.offset = 0;

			numkeys++;

			read(keyd_fd, &keybuf.size, sizeof(keybuf.size));
		}
	}
	
	return numkeys;
}

#define NEED_KEYID2UID 1
#define NEED_GETKEYSIGS 1
#define NEED_UPDATEKEYS 1
#include "keydb.c"
