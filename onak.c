/*
 * onak.c - An OpenPGP keyserver.
 *
 * This is the main swiss army knife binary.
 *
 * Jonathan McDowell <noodles@earth.li>
 * 
 * Copyright 2002 Project Purple
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "armor.h"
#include "keydb.h"
#include "keyid.h"
#include "keyindex.h"
#include "keystructs.h"
#include "mem.h"
#include "merge.h"
#include "onak-conf.h"
#include "parsekey.h"

int stdin_getchar(void *ctx, size_t count, unsigned char *c)
{
	int ic;

	do {
		ic = getchar();
		*c = ic;
		c++;
	} while ((ic != EOF) && (--count > 0));
	return (ic == EOF);
}

int stdout_putchar(void *ctx, size_t count, unsigned char *c)
{
	int i;

	for (i = 0; i < count; i++) {
		putchar(c[i]);
	}
	return 0;
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
		key_index(publickey, verbose, fingerprint, false);
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

void usage(void) {
	puts("onak " VERSION " - an OpenPGP keyserver.\n");
	puts("Usage:\n");
	puts("\tonak [options] <command> <parameters>\n");
	puts("\tCommands:\n");
	puts("\tadd    - read armored OpenPGP keys from stdin and add to the"
		" keyserver");
	puts("\tdelete - delete a given key from the keyserver");
	puts("\tget    - retrieves the key requested from the keyserver");
	puts("\tindex  - search for a key and list it");
	puts("\tvindex - search for a key and list it and its signatures");
}

int main(int argc, char *argv[])
{
	struct openpgp_packet_list	*packets = NULL;
	struct openpgp_packet_list	*list_end = NULL;
	struct openpgp_publickey	*keys = NULL;
	int				 rc = EXIT_SUCCESS;
	int				 result = 0;
	char				*search = NULL;
	char				*end = NULL;
	uint64_t			 keyid = 0;
	bool				 ishex = false;
	bool				 verbose = false;
	bool				 update = false;
	bool				 binary = false;
	bool				 fingerprint = false;
	int				 optchar;

	while ((optchar = getopt(argc, argv, "bfuv")) != -1 ) {
		switch (optchar) {
		case 'b': 
			binary = true;
			break;
		case 'f': 
			fingerprint = true;
			break;
		case 'u': 
			update = true;
			break;
		case 'v': 
			verbose = true;
			break;
		}
	}

	readconfig();

	if ((argc - optind) < 1) {
		usage();
	} else if (!strcmp("add", argv[optind])) {
		if (binary) {
			result = read_openpgp_stream(stdin_getchar, NULL,
				 &packets);
			if (verbose) {
				fprintf(stderr,
					"read_openpgp_stream: %d\n", result);
			}
		} else {
			dearmor_openpgp_stream(stdin_getchar, NULL, &packets);
		}
		if (packets != NULL) {
			result = parse_keys(packets, &keys);
			free_packet_list(packets);
			packets = NULL;
			if (verbose) {
				fprintf(stderr, "Finished reading %d keys.\n",
					result);
			}

			initdb();
			fprintf(stderr, "Got %d new keys.\n",
					update_keys(&keys, verbose));
			if (keys != NULL && update) {
				flatten_publickey(keys,
					&packets,
					&list_end);
				armor_openpgp_stream(stdout_putchar,
					NULL,
					packets);
				free_packet_list(packets);
				packets = NULL;
			}
			cleanupdb();
		} else {
			rc = 1;
			fprintf(stderr, "No keys read.\n");
		}

		if (keys != NULL) {
			free_publickey(keys);
			keys = NULL;
		} else {
			rc = 1;
			fprintf(stderr, "No changes.\n");
		}
	} else if ((argc - optind) == 2) {
		search = argv[optind+1];
		if (search != NULL) {
			keyid = strtoul(search, &end, 16);
			if (*search != 0 &&
					end != NULL &&
					*end == 0) {
				ishex = true;
			}
		}
		initdb();
		if (!strcmp("index", argv[optind])) {
			find_keys(search, keyid, ishex, fingerprint,
					false, false);
		} else if (!strcmp("vindex", argv[optind])) {
			find_keys(search, keyid, ishex, fingerprint,
					false, true);
		} else if (!strcmp("delete", argv[optind])) {
			delete_key(getfullkeyid(keyid), false);
		} else if (!strcmp("get", argv[optind])) {
			if (fetch_key(keyid, &keys, false)) {
				if (verbose) {
					fprintf(stderr, "Got key.\n");
				}
				flatten_publickey(keys,
						&packets,
						&list_end);
				armor_openpgp_stream(stdout_putchar,
						NULL,
						packets);
				free_packet_list(packets);
				packets = NULL;
			} else {
				puts("Key not found");
			}
		}
		cleanupdb();
	} else {
		usage();
	}

	cleanupconfig();

	return rc;
}
