/*
 * lookup.c - CGI to lookup keys.
 *
 * Copyright 2002-2005,2007-2009,2011 Jonathan McDowell <noodles@earth.li>
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

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "build-config.h"

#include "armor.h"
#include "charfuncs.h"
#include "cleankey.h"
#include "cleanup.h"
#include "getcgi.h"
#include "keydb.h"
#include "keyid.h"
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
#define OP_HGET    5

void find_keys(struct onak_dbctx *dbctx,
		char *search, uint64_t keyid,
		struct openpgp_fingerprint *fingerprint,
		bool ishex, bool isfp, bool dispfp, bool skshash,
		__unused bool exact, bool verbose, bool mrhkp)
{
	struct openpgp_publickey *publickey = NULL;
	int count = 0;

	if (ishex) {
		count = dbctx->fetch_key_id(dbctx, keyid, &publickey,
				false);
	} else if (isfp) {
		count = dbctx->fetch_key_fp(dbctx, fingerprint, &publickey,
				false);
	} else {
		count = dbctx->fetch_key_text(dbctx, search, &publickey);
	}
	if (publickey != NULL) {
		if (mrhkp) {
			printf("info:1:%d\n", count);
			mrkey_index(publickey);
		} else {
			key_index(dbctx, publickey, verbose, dispfp,
				skshash, true);
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

int main(int argc, char *argv[])
{
	char **params = NULL;
	int op = OP_UNKNOWN;
	int i, j;
	int indx = 0;
	bool dispfp = false;
	bool skshash = false;
	bool exact = false;
	bool ishex = false;
	bool isfp = false;
	bool mrhkp = false;
	uint64_t keyid = 0;
	struct openpgp_fingerprint fingerprint;
	char *search = NULL;
	char *end = NULL;
	struct openpgp_publickey *publickey = NULL;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	int result;
	struct skshash hash;
	struct onak_dbctx *dbctx;

	params = getcgivars(argc, argv);
	for (i = 0; params != NULL && params[i] != NULL; i += 2) {
		if (!strcmp(params[i], "op")) {
			if (!strcmp(params[i+1], "get")) {
				op = OP_GET;
			} else if (!strcmp(params[i+1], "hget")) {
				op = OP_HGET;
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
			if (search != NULL && strlen(search) == 42 &&
					search[0] == '0' && search[1] == 'x') {
				/* v4 fingerprint */
				fingerprint.length = 20;
				for (j = 0; j < 20; j++) {
					fingerprint.fp[j] = (hex2bin(
							search[2 + j * 2])
								<< 4) +
						hex2bin(search[3 + j * 2]);
				}
				isfp = true;
			} else if (search != NULL && strlen(search) == 66 &&
					search[0] == '0' && search[1] == 'x') {
				/* v5 fingerprint */
				fingerprint.length = 32;
				for (j = 0; j < 32; j++) {
					fingerprint.fp[j] = (hex2bin(
							search[2 + j * 2])
								<< 4) +
						hex2bin(search[3 + j * 2]);
				}
				isfp = true;
			} else if (search != NULL) {
				keyid = strtoull(search, &end, 16);
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
				dispfp = true;
			}
		} else if (!strcmp(params[i], "hash")) {
			if (!strcmp(params[i+1], "on")) {
				skshash = true;
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
		catchsignals();
		dbctx = config.dbinit(config.backend, false);
		if (dbctx == NULL) {
			logthing(LOGTHING_ERROR,
				"Failed to open key database.");
			goto err;
		}
		switch (op) {
		case OP_GET:
		case OP_HGET:
			if (op == OP_HGET) {
				parse_skshash(search, &hash);
				result = dbctx->fetch_key_skshash(dbctx,
					&hash, &publickey);
			} else if (ishex) {
				result = dbctx->fetch_key_id(dbctx, keyid,
					&publickey, false);
			} else if (isfp) {
				result = dbctx->fetch_key_fp(dbctx,
					&fingerprint, &publickey, false);
			} else {
				result = dbctx->fetch_key_text(dbctx,
					search,
					&publickey);
			}
			if (result) {
				logthing(LOGTHING_NOTICE, 
					"Found %d key(s) for search %s",
					result,
					search);
				puts("<pre>");
				cleankeys(dbctx, &publickey,
						config.clean_policies);
				flatten_publickey(publickey,
							&packets,
							&list_end);
				armor_openpgp_stream(stdout_putchar,
						NULL,
						packets);
				puts("</pre>");
			} else {
				logthing(LOGTHING_NOTICE,
					"Failed to find key for search %s",
					search);
				puts("Key not found");
			}
			break;
		case OP_INDEX:
			find_keys(dbctx, search, keyid, &fingerprint,
					ishex, isfp, dispfp, skshash,
					exact, false, mrhkp);
			break;
		case OP_VINDEX:
			find_keys(dbctx, search, keyid, &fingerprint,
					ishex, isfp, dispfp, skshash,
					exact, true, mrhkp);
			break;
		case OP_PHOTO:
			if (isfp) {
				dbctx->fetch_key_fp(dbctx, &fingerprint,
					&publickey, false);
			} else {
				dbctx->fetch_key_id(dbctx, keyid,
					&publickey, false);
			}
			if (publickey != NULL) {
				unsigned char *photo = NULL;
				size_t         length = 0;

				if (getphoto(publickey, indx, &photo,
						&length) == ONAK_E_OK) {
					fwrite(photo,
							1,
							length,
							stdout);
				}
				free_publickey(publickey);
				publickey = NULL;
			}
			break;
		default:
			puts("Unknown operation!");
		}
		dbctx->cleanupdb(dbctx);
err:
		cleanuplogthing();
		cleanupconfig();
	}
	if (!mrhkp) {
		puts("<hr>");
		puts("Produced by onak " ONAK_VERSION );
		end_html();
	}

	if (search != NULL) {
		free(search);
		search = NULL;
	}
	
	return (EXIT_SUCCESS);
}
