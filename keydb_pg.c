/*
 * keydb_pg.c - Routines to store and fetch keys in a PostGres database.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#include <postgresql/libpq-fe.h>
#include <postgresql/libpq/libpq-fs.h>

//#include <libpq-fe.h>
//#include <libpq/libpq-fs.h>
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
#include "keyindex.h"
#include "keystructs.h"
#include "mem.h"
#include "parsekey.h"

/**
 *	dbconn - our connection to the database.
 */
static PGconn *dbconn = NULL;

/**
 *	keydb_fetchchar - Fetches a char from a file.
 */
static int keydb_fetchchar(void *fd, size_t count, unsigned char *c)
{
	return (!lo_read(dbconn, *(int *) fd, c, count));
}

/**
 *	keydb_putchar - Puts a char to a file.
 */
static int keydb_putchar(void *fd, unsigned char c)
{
	return !(lo_write(dbconn, *(int *) fd, &c, sizeof(c)));
}

/**
 *	initdb - Initialize the key database.
 *
 *	This function should be called before any of the other functions in
 *	this file are called in order to allow the DB to be initialized ready
 *	for access.
 */
void initdb(void)
{
	dbconn = PQsetdbLogin(NULL, // host
			NULL, // port
			NULL, // options
			NULL, // tty
			"noodles", // database
			NULL,  //login
			NULL); // password

	if (PQstatus(dbconn) == CONNECTION_BAD) {
		fprintf(stderr, "Connection to database failed.\n");
		fprintf(stderr, "%s\n", PQerrorMessage(dbconn));
		PQfinish(dbconn);
		dbconn = NULL;
		exit(1);
	}
}

/**
 *	cleanupdb - De-initialize the key database.
 *
 *	This function should be called upon program exit to allow the DB to
 *	cleanup after itself.
 */
void cleanupdb(void)
{
	PQfinish(dbconn);
	dbconn = NULL;
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
	PGresult *result = NULL;
	char *oids = NULL;
	char statement[1024];
	int fd = -1;
	Oid key_oid;

	result = PQexec(dbconn, "BEGIN");
	PQclear(result);
	
	snprintf(statement, 1023,
			"SELECT keydata FROM onak_keys WHERE keyid = '%llX'",
			keyid & 0xFFFFFFFF);
	result = PQexec(dbconn, statement);

	if (PQresultStatus(result) == PGRES_TUPLES_OK &&
			PQntuples(result) == 1) {
		oids = PQgetvalue(result, 0, 0);
		key_oid = (Oid) atoi(oids);

		fd = lo_open(dbconn, key_oid, INV_READ);
		if (fd < 0) {
			fprintf(stderr, "Can't open large object.\n");
		} else {
			read_openpgp_stream(keydb_fetchchar, &fd, &packets);
			parse_keys(packets, publickey);
			lo_close(dbconn, fd);
		}
	} else if (PQresultStatus(result) != PGRES_TUPLES_OK) {
		fprintf(stderr, "Problem retrieving key (%llX) from DB.\n",
				keyid);
	}

	PQclear(result);

	result = PQexec(dbconn, "COMMIT");
	PQclear(result);
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
	PGresult *result = NULL;
	char statement[1024];
	Oid key_oid;
	int fd;


	/*
	 * Delete the key if we already have it.
	 *
	 * TODO: Can we optimize this perhaps? Possibly when other data is
	 * involved as well? I suspect this is easiest and doesn't make a lot
	 * of difference though - the largest chunk of data is the keydata and
	 * it definitely needs updated.
	 */
	delete_key(get_keyid(publickey));

	result = PQexec(dbconn, "BEGIN");
	PQclear(result);

	next = publickey->next;
	publickey->next = NULL;
	flatten_publickey(publickey, &packets, &list_end);
	publickey->next = next;
		
	key_oid = lo_creat(dbconn, INV_READ | INV_WRITE);
	if (key_oid == 0) {
		fprintf(stderr, "Can't create key OID\n");
	} else {
		fd = lo_open(dbconn, key_oid, INV_WRITE);
		write_openpgp_stream(keydb_putchar, &fd, packets);
		lo_close(dbconn, fd);
	}

	snprintf(statement, 1023, 
			"INSERT INTO onak_keys (keyid, keydata) VALUES "
			"('%llX', '%d')", 
			get_keyid(publickey) & 0xFFFFFFFF,
			key_oid);
	result = PQexec(dbconn, statement);

	if (PQresultStatus(result) != PGRES_COMMAND_OK) {
		fprintf(stderr, "Problem storing key in DB.\n");
		fprintf(stderr, "%s\n", PQresultErrorMessage(result));
	}
	PQclear(result);

	result = PQexec(dbconn, "COMMIT");
	PQclear(result);
	
	return 0;
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
	PGresult *result = NULL;
	char *oids = NULL;
	char statement[1024];
	int found = 1;
	Oid key_oid;

	result = PQexec(dbconn, "BEGIN");
	PQclear(result);
	
	snprintf(statement, 1023,
			"SELECT keydata FROM onak_keys WHERE keyid = '%llX'",
			keyid & 0xFFFFFFFF);
	result = PQexec(dbconn, statement);

	if (PQresultStatus(result) == PGRES_TUPLES_OK &&
			PQntuples(result) == 1) {
		found = 0;
		oids = PQgetvalue(result, 0, 0);
		key_oid = (Oid) atoi(oids);
		lo_unlink(dbconn, key_oid);
		PQclear(result);
		snprintf(statement, 1023,
			"DELETE * FROM onak_keys WHERE keyid = '%llX'",
			keyid & 0xFFFFFFFF);
		result = PQexec(dbconn, statement);
	} else if (PQresultStatus(result) != PGRES_TUPLES_OK) {
		fprintf(stderr, "Problem retrieving key (%llX) from DB.\n",
				keyid);
	}

	PQclear(result);

	result = PQexec(dbconn, "COMMIT");
	PQclear(result);
	return (found);
}

/*
 * Include the basic keydb routines.
 */
#include "keydb.c"
