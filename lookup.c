/*
 * lookup.c - CGI to lookup keys.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

//#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "armor.h"
#include "getcgi.h"
#include "keydb.h"
#include "keyindex.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"

#define OP_UNKNOWN 0
#define OP_GET     1
#define OP_INDEX   2
#define OP_VINDEX  3

int putnextchar(void *ctx, size_t count, unsigned char *c)
{
	return printf("%.*s", (int) count, c);
}

void find_keys(char *search, uint64_t keyid, bool ishex,
		bool fingerprint, bool exact, bool verbose)
{
	struct openpgp_publickey *publickey = NULL;
	int count = 0;

	if (ishex) {
		count = fetch_key(keyid, &publickey, false);
	} else {
		count = fetch_key_text(search, &publickey);
	}
	if (publickey != NULL) {
		key_index(publickey, verbose, fingerprint, true);
		free_publickey(publickey);
	} else if (count == 0) {
		puts("Key not found.");
	} else {
		printf("Found %d keys, but maximum number to return is %d.\n",
				count,
				config.maxkeys);
		puts("Try again with a more specific search.");
	}
}

int main(int argc, char *argv[])
{
	char **params = NULL;
	int op = OP_UNKNOWN;
	int i;
	bool fingerprint = false;
	bool exact = false;
	bool ishex = false;
	uint64_t keyid = 0;
	char *search = NULL;
	char *end = NULL;
	struct openpgp_publickey *publickey = NULL;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;

	params = getcgivars(argc, argv);
	for (i = 0; params != NULL && params[i] != NULL; i += 2) {
		if (!strcmp(params[i], "op")) {
			if (!strcmp(params[i+1], "get")) {
				op = OP_GET;
			} else if (!strcmp(params[i+1], "index")) {
				op = OP_INDEX;
			} else if (!strcmp(params[i+1], "vindex")) {
				op = OP_VINDEX;
			}
		} else if (!strcmp(params[i], "search")) {
			search = params[i+1];
			params[i+1] = NULL;
			if (search != NULL) {
				keyid = strtoul(search, &end, 16);
				if (*search != 0 &&
						end != NULL &&
						*end == 0) {
					ishex = true;
				}
			}
		} else if (!strcmp(params[i], "fingerprint")) {
			if (!strcmp(params[i+1], "on")) {
				fingerprint = true;
			}
		} else if (!strcmp(params[i], "exact")) {
			if (!strcmp(params[i+1], "on")) {
				exact = true;
			}
		}
		free(params[i]);
		params[i] = NULL;
		if (params[i+1] != NULL) {
			free(params[i+1]);
			params[i+1] = NULL;
		}
	}
	if (params != NULL) {
		free(params);
		params = NULL;
	}

	start_html("Lookup of key");

	if (op == OP_UNKNOWN) {
		puts("Error: No operation supplied.");
	} else if (search == NULL) {
		puts("Error: No key to search for supplied.");
	} else {
		initdb();
		switch (op) {
		case OP_GET:
			if (fetch_key(keyid, &publickey, false)) {
				puts("<pre>");
				flatten_publickey(publickey,
							&packets,
							&list_end);
				armor_openpgp_stream(putnextchar,
						NULL,
						packets);
				puts("</pre>");
			} else {
				puts("Key not found");
			}
			break;
		case OP_INDEX:
			find_keys(search, keyid, ishex, fingerprint, exact,
					false);
			break;
		case OP_VINDEX:
			find_keys(search, keyid, ishex, fingerprint, exact,
					true);
			break;
		default:
			puts("Unknown operation!");
		}
		cleanupdb();
	}
	puts("<hr>");
	puts("Produced by onak " VERSION " by Jonathan McDowell");
	end_html();

	if (search != NULL) {
		free(search);
		search = NULL;
	}
	
	return (EXIT_SUCCESS);
}
