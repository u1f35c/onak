/*
 * onak.c - An OpenPGP keyserver.
 *
 * This is the main swiss army knife binary.
 *
 * Jonathan McDowell <noodles@earth.li>
 * 
 * Copyright 2002 Project Purple
 */

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "armor.h"
#include "charfuncs.h"
#include "cleankey.h"
#include "cleanup.h"
#include "config.h"
#include "keydb.h"
#include "keyid.h"
#include "keyindex.h"
#include "keystructs.h"
#include "log.h"
#include "mem.h"
#include "merge.h"
#include "onak-conf.h"
#include "parsekey.h"
#include "photoid.h"

void find_keys(char *search, uint64_t keyid, bool ishex,
		bool fingerprint, bool exact, bool verbose)
{
	struct openpgp_publickey *publickey = NULL;
	int count = 0;

	if (ishex) {
		count = config.dbbackend->fetch_key(keyid, &publickey, false);
	} else {
		count = config.dbbackend->fetch_key_text(search, &publickey);
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

struct dump_ctx {
	int count;
	int maxcount;
	int fd;
	int filenum;
	char *filebase;
};

void dump_func(void *ctx, struct openpgp_publickey *key)
{
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct dump_ctx *state;
	char filename[1024];

	state = (struct dump_ctx *) ctx;

	if (state->fd == -1 || state->count++ > state->maxcount) {
		if (state->fd != -1) {
			close(state->fd);
			state->fd = -1;
		}
		snprintf(filename, 1023, state->filebase, state->filenum);
		state->fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0640);
		state->filenum++;
		state->count = 0;
	}
	flatten_publickey(key, &packets, &list_end);
	write_openpgp_stream(file_putchar, &state->fd, packets);
	free_packet_list(packets);
	packets = list_end = NULL;

	return;
}

void usage(void) {
	puts("onak " ONAK_VERSION " - an OpenPGP keyserver.\n");
	puts("Usage:\n");
	puts("\tonak [options] <command> <parameters>\n");
	puts("\tCommands:\n");
	puts("\tadd      - read armored OpenPGP keys from stdin and add to the"
		" keyserver");
	puts("\tclean    - read armored OpenPGP keys from stdin, run the"
		" cleaning\n\t       	   routines against them and dump to"
		" stdout");
	puts("\tdelete   - delete a given key from the keyserver");
	puts("\tdump     - dump all the keys from the keyserver to a file or"
		" files\n\t           starting keydump*");
	puts("\tget      - retrieves the key requested from the keyserver");
	puts("\tgetphoto - retrieves the first photoid on the given key and"
		" dumps to\n\t           stdout");
	puts("\tindex    - search for a key and list it");
	puts("\tvindex   - search for a key and list it and its signatures");
}

int main(int argc, char *argv[])
{
	struct openpgp_packet_list	*packets = NULL;
	struct openpgp_packet_list	*list_end = NULL;
	struct openpgp_publickey	*keys = NULL;
	char				*configfile = NULL;
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
	struct dump_ctx                  dumpstate;

	while ((optchar = getopt(argc, argv, "bc:fuv")) != -1 ) {
		switch (optchar) {
		case 'b': 
			binary = true;
			break;
		case 'c':
			configfile = strdup(optarg);
			break;
		case 'f': 
			fingerprint = true;
			break;
		case 'u': 
			update = true;
			break;
		case 'v': 
			verbose = true;
			setlogthreshold(LOGTHING_INFO);
			break;
		}
	}

	readconfig(configfile);
	initlogthing("onak", config.logfile);
	catchsignals();

	if ((argc - optind) < 1) {
		usage();
	} else if (!strcmp("dump", argv[optind])) {
		config.dbbackend->initdb(true);
		dumpstate.count = dumpstate.filenum = 0;
		dumpstate.maxcount = 100000;
		dumpstate.fd = -1;
		dumpstate.filebase = "keydump.%d.pgp";
		config.dbbackend->iterate_keys(dump_func, &dumpstate);
		if (dumpstate.fd != -1) {
			close(dumpstate.fd);
			dumpstate.fd = -1;
		}
		config.dbbackend->cleanupdb();
	} else if (!strcmp("add", argv[optind])) {
		if (binary) {
			result = read_openpgp_stream(stdin_getchar, NULL,
				 &packets, 0);
			logthing(LOGTHING_INFO,
					"read_openpgp_stream: %d", result);
		} else {
			dearmor_openpgp_stream(stdin_getchar, NULL, &packets);
		}
		if (packets != NULL) {
			result = parse_keys(packets, &keys);
			free_packet_list(packets);
			packets = NULL;
			logthing(LOGTHING_INFO, "Finished reading %d keys.",
					result);

			result = cleankeys(keys);
			logthing(LOGTHING_INFO, "%d keys cleaned.",
					result);

			config.dbbackend->initdb(false);
			logthing(LOGTHING_NOTICE, "Got %d new keys.",
					config.dbbackend->update_keys(&keys,
					false));
			if (keys != NULL && update) {
				flatten_publickey(keys,
					&packets,
					&list_end);
				if (binary) {
					write_openpgp_stream(stdout_putchar,
							NULL,
						 	packets);
				} else {
					armor_openpgp_stream(stdout_putchar,
						NULL,
						packets);
				}
				free_packet_list(packets);
				packets = NULL;
			}
			config.dbbackend->cleanupdb();
		} else {
			rc = 1;
			logthing(LOGTHING_NOTICE, "No keys read.");
		}

		if (keys != NULL) {
			free_publickey(keys);
			keys = NULL;
		} else {
			rc = 1;
			logthing(LOGTHING_NOTICE, "No changes.");
		}
	} else if (!strcmp("clean", argv[optind])) {
		if (binary) {
			result = read_openpgp_stream(stdin_getchar, NULL,
				 &packets, 0);
			logthing(LOGTHING_INFO,
					"read_openpgp_stream: %d", result);
		} else {
			dearmor_openpgp_stream(stdin_getchar, NULL, &packets);
		}

		if (packets != NULL) {
			result = parse_keys(packets, &keys);
			free_packet_list(packets);
			packets = NULL;
			logthing(LOGTHING_INFO, "Finished reading %d keys.",
					result);

			if (keys != NULL) {
				result = cleankeys(keys);
				logthing(LOGTHING_INFO, "%d keys cleaned.",
						result);

				flatten_publickey(keys,
					&packets,
					&list_end);

				if (binary) {
					write_openpgp_stream(stdout_putchar,
							NULL,
						 	packets);
				} else {
					armor_openpgp_stream(stdout_putchar,
						NULL,
						packets);
				}
				free_packet_list(packets);
				packets = NULL;
			}
		} else {
			rc = 1;
			logthing(LOGTHING_NOTICE, "No keys read.");
		}
		
		if (keys != NULL) {
			free_publickey(keys);
			keys = NULL;
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
		config.dbbackend->initdb(false);
		if (!strcmp("index", argv[optind])) {
			find_keys(search, keyid, ishex, fingerprint,
					false, false);
		} else if (!strcmp("vindex", argv[optind])) {
			find_keys(search, keyid, ishex, fingerprint,
					false, true);
		} else if (!strcmp("getphoto", argv[optind])) {
			if (!ishex) {
				puts("Can't get a key on uid text."
					" You must supply a keyid.");
			} else if (config.dbbackend->fetch_key(keyid, &keys,
					false)) {
				unsigned char *photo = NULL;
				size_t         length = 0;

				if (getphoto(keys, 0, &photo, &length)) {
					fwrite(photo,
						1,
						length,
						stdout);
				}
				free_publickey(keys);
				keys = NULL;
			} else {
				puts("Key not found");
			}
		} else if (!strcmp("delete", argv[optind])) {
			config.dbbackend->delete_key(
					config.dbbackend->getfullkeyid(keyid),
					false);
		} else if (!strcmp("get", argv[optind])) {
			if (!ishex) {
				puts("Can't get a key on uid text."
					" You must supply a keyid.");
			} else if (config.dbbackend->fetch_key(keyid, &keys,
					false)) {
				logthing(LOGTHING_INFO, "Got key.");
				flatten_publickey(keys,
						&packets,
						&list_end);
				free_publickey(keys);
				if (binary) {
					write_openpgp_stream(stdout_putchar,
						NULL,
						packets);
				} else {
					armor_openpgp_stream(stdout_putchar,
						NULL,
						packets);
				}
				free_packet_list(packets);
				packets = NULL;
			} else {
				puts("Key not found");
			}
		}
		config.dbbackend->cleanupdb();
	} else {
		usage();
	}

	cleanuplogthing();
	cleanupconfig();

	return rc;
}
