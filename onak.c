/*
 * onak.c - An OpenPGP keyserver.
 *
 * This is the main swiss army knife binary.
 *
 * Copyright 2002 Jonathan McDowell <noodles@earth.li>
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
 * this program.  If not, see <https://www.gnu.org/licenses/>.
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
#include "version.h"

void find_keys(struct onak_dbctx *dbctx,
		char *search, uint64_t keyid,
		struct openpgp_fingerprint *fingerprint,
		bool ishex, bool isfp, bool dispfp, bool skshash,
		bool exact, bool verbose)
{
	struct openpgp_publickey *publickey = NULL;
	int count = 0;

	if (ishex) {
		count = dbctx->fetch_key_id(dbctx, keyid, &publickey,
				false);
	} else if (isfp) {
		count = dbctx->fetch_key_fp(dbctx, fingerprint,
				&publickey, false);
	} else {
		count = dbctx->fetch_key_text(dbctx, search, &publickey);
	}
	if (publickey != NULL) {
		key_index(dbctx, publickey, verbose, dispfp, skshash,
			false);
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

/**
 * @brief Context for the keyserver dumping function
 */
struct dump_ctx {
	/** Keys we've dumped so far to this file */
	int count;
	/** Maximum keys to dump per file */
	int maxcount;
	/** File descriptor for the current dump file */
	int fd;
	/** Number of the current dump file */
	int filenum;
	/** Base filename to use for dump files */
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

static uint8_t hex2bin(char c)
{
	if (c >= '0' && c <= '9') {
		return (c - '0');
	} else if (c >= 'a' && c <= 'f') {
		return (c - 'a' + 10);
	} else if (c >= 'A' && c <= 'F') {
		return (c - 'A' + 10);
	}

	return 255;
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
	puts("\treindex  - retrieve and re-store a key in the backend db");
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
	int				 i;
	bool				 ishex = false;
	bool				 isfp = false;
	bool				 update = false;
	bool				 binary = false;
	bool				 dispfp = false;
	bool				 skshash = false;
	int				 optchar;
	struct dump_ctx                  dumpstate;
	struct skshash			 hash;
	struct onak_dbctx		*dbctx;
	struct openpgp_fingerprint	 fingerprint;

	while ((optchar = getopt(argc, argv, "bc:fsuv")) != -1 ) {
		switch (optchar) {
		case 'b': 
			binary = true;
			break;
		case 'c':
			configfile = strdup(optarg);
			break;
		case 'f': 
			dispfp = true;
			break;
		case 's': 
			skshash = true;
			break;
		case 'u': 
			update = true;
			break;
		case 'v': 
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
		dbctx = config.dbinit(config.backend, true);
		dumpstate.count = dumpstate.filenum = 0;
		dumpstate.maxcount = 100000;
		dumpstate.fd = -1;
		dumpstate.filebase = "keydump.%d.pgp";
		dbctx->iterate_keys(dbctx, dump_func, &dumpstate);
		if (dumpstate.fd != -1) {
			close(dumpstate.fd);
			dumpstate.fd = -1;
		}
		dbctx->cleanupdb(dbctx);
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

			result = cleankeys(&keys, config.clean_policies);
			logthing(LOGTHING_INFO, "%d keys cleaned.",
					result);

			dbctx = config.dbinit(config.backend, false);
			logthing(LOGTHING_NOTICE, "Got %d new keys.",
					dbctx->update_keys(dbctx, &keys,
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
			dbctx->cleanupdb(dbctx);
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
				result = cleankeys(&keys,
						config.clean_policies);
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
	} else if (!strcmp("dumpconfig", argv[optind])) {
		if ((argc - optind) == 2) {
			writeconfig(argv[optind + 1]);
		} else {
			/* Dump config to stdout */
			writeconfig(NULL);
		}
	} else if ((argc - optind) == 2) {
		search = argv[optind+1];
		if (search != NULL && strlen(search) == 42 &&
				search[0] == '0' && search[1] == 'x') {
			fingerprint.length = MAX_FINGERPRINT_LEN;
			for (i = 0; i < MAX_FINGERPRINT_LEN; i++) {
				fingerprint.fp[i] =
					(hex2bin(search[2 + i * 2]) << 4) +
						hex2bin(search[3 + i * 2]);
			}
			isfp = true;
		} else if (search != NULL) {
			keyid = strtouq(search, &end, 16);
			if (*search != 0 &&
					end != NULL &&
					*end == 0) {
				ishex = true;
			}
		}
		dbctx = config.dbinit(config.backend, false);
		if (!strcmp("index", argv[optind])) {
			find_keys(dbctx, search, keyid, &fingerprint, ishex,
					isfp, dispfp, skshash,
					false, false);
		} else if (!strcmp("vindex", argv[optind])) {
			find_keys(dbctx, search, keyid, &fingerprint, ishex,
					isfp, dispfp, skshash,
					false, true);
		} else if (!strcmp("getphoto", argv[optind])) {
			if (!ishex) {
				puts("Can't get a key on uid text."
					" You must supply a keyid.");
			} else if (dbctx->fetch_key_id(dbctx, keyid, &keys,
					false)) {
				unsigned char *photo = NULL;
				size_t         length = 0;

				if (getphoto(keys, 0, &photo,
						&length) == ONAK_E_OK) {
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
			dbctx->delete_key(dbctx,
					dbctx->getfullkeyid(dbctx, keyid),
					false);
		} else if (!strcmp("get", argv[optind])) {
			if (!(ishex || isfp)) {
				puts("Can't get a key on uid text."
					" You must supply a keyid / "
					"fingerprint.");
			} else if ((isfp &&
					dbctx->fetch_key_fp(dbctx,
						&fingerprint,
						&keys, false)) ||
					(ishex &&
					dbctx->fetch_key_id(dbctx, keyid,
						&keys, false))) {
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
		} else if (!strcmp("hget", argv[optind])) {
			if (!parse_skshash(search, &hash)) {
				puts("Couldn't parse sks hash.");
			} else if (dbctx->fetch_key_skshash(dbctx, &hash,
					&keys)) {
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
		} else if (!strcmp("reindex", argv[optind])) {
			dbctx->starttrans(dbctx);
			if (dbctx->fetch_key_id(dbctx, keyid, &keys, true)) {
				dbctx->delete_key(dbctx, keyid, true);
				cleankeys(&keys, config.clean_policies);
				dbctx->store_key(dbctx, keys, true, false);
			} else {
				puts("Key not found");
			}
			dbctx->endtrans(dbctx);
		}
		dbctx->cleanupdb(dbctx);
	} else {
		usage();
	}

	cleanuplogthing();
	cleanupconfig();
	free(configfile);

	return rc;
}
