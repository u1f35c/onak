/*
 * lookup.c - CGI to lookup keys.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 *
 * $Id: lookup.c,v 1.15 2004/05/27 01:25:37 noodles Exp $
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "armor.h"
#include "charfuncs.h"
#include "getcgi.h"
#include "keydb.h"
#include "keyindex.h"
#include "log.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"
#include "photoid.h"

#define OP_UNKNOWN 0
#define OP_GET     1
#define OP_INDEX   2
#define OP_VINDEX  3
#define OP_PHOTO   4

void find_keys(char *search, uint64_t keyid, bool ishex,
		bool fingerprint, bool exact, bool verbose, bool mrhkp)
{
	struct openpgp_publickey *publickey = NULL;
	int count = 0;

	if (ishex) {
		count = fetch_key(keyid, &publickey, false);
	} else {
		count = fetch_key_text(search, &publickey);
	}
	if (publickey != NULL) {
		if (mrhkp) {
			printf("info:1:%d\n", count);
			mrkey_index(publickey);
		} else {
			key_index(publickey, verbose, fingerprint, true);
		}
		free_publickey(publickey);
	} else if (count == 0) {
		if (mrhkp) {
			puts("info:1:0");
		} else {
			puts("Key not found.");
		}
	} else {
		if (mrhkp) {
			puts("info:1:0");
		} else {
			printf("Found %d keys, but maximum number to return"
				" is %d.\n",
				count,
				config.maxkeys);
			puts("Try again with a more specific search.");
		}
	}
}

int main(int argc, char *argv[])
{
	char **params = NULL;
	int op = OP_UNKNOWN;
	int i;
	int indx = 0;
	bool fingerprint = false;
	bool exact = false;
	bool ishex = false;
	bool mrhkp = false;
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
			} else if (!strcmp(params[i+1], "photo")) {
				op = OP_PHOTO;
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
		} else if (!strcmp(params[i], "idx")) {
			indx = atoi(params[i+1]);
		} else if (!strcmp(params[i], "fingerprint")) {
			if (!strcmp(params[i+1], "on")) {
				fingerprint = true;
			}
		} else if (!strcmp(params[i], "exact")) {
			if (!strcmp(params[i+1], "on")) {
				exact = true;
			}
		} else if (!strcmp(params[i], "options")) {
			/*
			 * TODO: We should be smarter about this; options may
			 * have several entries. For now mr is the only valid
			 * one though.
			 */
			if (!strcmp(params[i+1], "mr")) {
				mrhkp = true;
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

	if (mrhkp) {
		puts("Content-Type: text/plain\n");
	} else if (op == OP_PHOTO) {
		puts("Content-Type: image/jpeg\n");
	} else {
		start_html("Lookup of key");
	}

	if (op == OP_UNKNOWN) {
		puts("Error: No operation supplied.");
	} else if (search == NULL) {
		puts("Error: No key to search for supplied.");
	} else {
		readconfig(NULL);
		initlogthing("lookup", config.logfile);
		initdb(true);
		switch (op) {
		case OP_GET:
			logthing(LOGTHING_NOTICE, "Getting keyid %llX",
					keyid);
			if (fetch_key(keyid, &publickey, false)) {
				puts("<pre>");
				flatten_publickey(publickey,
							&packets,
							&list_end);
				armor_openpgp_stream(stdout_putchar,
						NULL,
						packets);
				puts("</pre>");
			} else {
				puts("Key not found");
			}
			break;
		case OP_INDEX:
			find_keys(search, keyid, ishex, fingerprint, exact,
					false, mrhkp);
			break;
		case OP_VINDEX:
			find_keys(search, keyid, ishex, fingerprint, exact,
					true, mrhkp);
			break;
		case OP_PHOTO:
			if (fetch_key(keyid, &publickey, false)) {
				struct openpgp_packet *photo = NULL;
				photo = getphoto(publickey, 0);
				if (photo != NULL) {
					fwrite(photo->data+19,
							1,
							(photo->length - 19),
							stdout);
				}
				free_publickey(publickey);
				publickey = NULL;
			}
			break;
		default:
			puts("Unknown operation!");
		}
		cleanupdb();
		cleanuplogthing();
		cleanupconfig();
	}
	if (!mrhkp) {
		puts("<hr>");
		puts("Produced by onak " VERSION " by Jonathan McDowell");
		end_html();
	}

	if (search != NULL) {
		free(search);
		search = NULL;
	}
	
	return (EXIT_SUCCESS);
}
