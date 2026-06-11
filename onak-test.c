/*
 * onak-test.c - Basic test program for onak
 *
 * Copyright 2026 Jonathan McDowell <noodles@earth.li>
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
#define _XOPEN_SOURCE 700

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "charfuncs.h"
#include "cleankey.h"
#include "keyindex.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"

int main() {
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_publickey *keys = NULL;
	struct onak_db_config dummy_backend;
	struct onak_dbctx *dbctx;
	char *dbpath, *lastslash;
	int result = 0;

	/* Build a minimal dummy DB config */
	dummy_backend.type = "dummy";
	config.db_backend = "dummy";
	config.backend = &dummy_backend;

	/*
	 * We assume we're being run from the build dir, so work out the DB
	 * path based on ours.
	 */
	dbpath = realpath("/proc/self/exe", NULL);
	lastslash = strrchr(dbpath, '/');
	if (lastslash != NULL) {
		*lastslash = 0;
	}
	config.backends_dir = malloc(strlen(dbpath) + strlen("/keydb") + 1);
	sprintf(config.backends_dir, "%s/keydb", dbpath);
	free(dbpath);

	result = read_openpgp_stream(stdin_getchar, NULL,
		 &packets, 0);

	if (packets == NULL) {
		printf(" * No packets read.\n");
		return 0;
	}

	result = parse_keys(packets, &keys);
	free_packet_list(packets);
	packets = NULL;

	if (keys == NULL) {
		printf(" * No keys read.\n");
		return 0;
	}

	printf(" * Finished reading %d keys.\n", result);

	dbctx = config.dbinit(config.backend, false);

	key_index(dbctx, keys, true, true, true, false);

	printf(" * Cleaning keys.\n");

	result = cleankeys(dbctx, &keys,
			ONAK_CLEAN_VERIFY_SIGNATURES);

	printf(" * Cleaned %d keys.\n", result);

	dbctx->cleanupdb(dbctx);
	dbctx = NULL;

	free_publickey(keys);

	free(config.backends_dir);
	config.backends_dir = NULL;
}
