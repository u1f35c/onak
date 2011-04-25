/*
 * hashquery.c - CGI to handle SKS style /pks/hashquery requests
 *
 * Copyright 2011 Jonathan McDowell <noodles@earth.li>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "charfuncs.h"
#include "cleanup.h"
#include "keyid.h"
#include "log.h"
#include "marshal.h"
#include "mem.h"
#include "onak-conf.h"

void doerror(char *error)
{
	printf("Content-Type: text/plain\n\n");
	printf("%s", error);
	cleanuplogthing();
	cleanupconfig();
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	char *request_method;
	int count, found, i;
	uint8_t **hashes;
	struct buffer_ctx cgipostbuf;
	struct openpgp_publickey **keys;

	readconfig(NULL);
	initlogthing("hashquery", config.logfile);

	request_method = getenv("REQUEST_METHOD");
	if (request_method == NULL || strcmp(request_method, "POST") != 0) {
		doerror("hashquery must be a HTTP POST request.\n");
	}

	if (!(cgipostbuf.size = atoi(getenv("CONTENT_LENGTH")))) {
		doerror("Must provide a content length.\n");
	}

	cgipostbuf.offset = 0;
	cgipostbuf.buffer = malloc(cgipostbuf.size);
	if (cgipostbuf.buffer == NULL) {
		doerror("Couldn't allocate memory for query content.\n");
	}

	if (!fread(cgipostbuf.buffer, cgipostbuf.size, 1, stdin)) {
		doerror("Couldn't read query.\n");
	}

	hashes = (uint8_t **) unmarshal_array(buffer_fetchchar, &cgipostbuf,
			(void * (*)(int (*)(void *, size_t,  void *), void *))
				unmarshal_skshash, &count);

	free(cgipostbuf.buffer);
	cgipostbuf.buffer = NULL;
	cgipostbuf.size = cgipostbuf.offset = 0;

	if (hashes == NULL) {
		doerror("No hashes supplied.\n");
	}

	found = 0;
	keys = calloc(sizeof(struct openpgp_publickey *), count);
	if (keys == NULL) {
		doerror("Couldn't allocate memory for reply.\n");
	}

	if (config.dbbackend->fetch_key_skshash == NULL) {
		doerror("Can't fetch by skshash with this backend.");
	}

	catchsignals();
	config.dbbackend->initdb(false);

	for (i = 0; i < count; i++) {
		config.dbbackend->fetch_key_skshash(
				(struct skshash *) hashes[i], &keys[found]);
		if (keys[found] != NULL) {
			found++;
		}
		free(hashes[i]);
		hashes[i] = NULL;
	}
	free(hashes);
	hashes = NULL;

	config.dbbackend->cleanupdb();

	puts("Content-Type: pgp/keys\n");
	marshal_array(stdout_putchar, NULL,
			(void (*)(int (*)(void *, size_t,  void *),
					void *, const void *))
				marshal_publickey, (void **) keys, found);
	printf("\n");

	for (i = 0; i < found; i++) {
		free_publickey(keys[i]);
	}
	free(keys);

	cleanuplogthing();
	cleanupconfig();
}
