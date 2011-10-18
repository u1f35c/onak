/*
 * gpgwww.c - www interface to path finder.
 *
 * Copyright 2001-2004 Jonathan McDowell <noodles@earth.li>
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
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "armor.h"
#include "charfuncs.h"
#include "cleanup.h"
#include "getcgi.h"
#include "hash.h"
#include "keydb.h"
#include "log.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"
#include "stats.h"
#include "version.h"

#define OP_UNKNOWN 0
#define OP_GET     1

int parsecgistuff(char **cgiparams, uint64_t *from, uint64_t *to)
{
	int i = 0;
	int op = OP_UNKNOWN;

	if (cgiparams != NULL) {
		i = 0;
		while (cgiparams[i] != NULL) {
			if (!strcmp(cgiparams[i], "to")) {
				*to = strtoul(cgiparams[i+1], NULL, 16);
			} else if (!strcmp(cgiparams[i], "from")) {
				*from = strtoul(cgiparams[i+1], NULL, 16);
			} else if (!strcmp(cgiparams[i], "op")) {
				if (!strcmp(cgiparams[i+1], "get")) {
					op = OP_GET;
				}
			}
			i += 2;
		}
	}

	return op;
}

int getkeyspath(uint64_t have, uint64_t want, int count)
{
	struct openpgp_publickey *publickey = NULL;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct stats_key *keyinfoa, *keyinfob, *curkey;
	uint64_t fullhave, fullwant;
	int pathlen = 0;

	fullhave = config.dbbackend->getfullkeyid(have);
	fullwant = config.dbbackend->getfullkeyid(want);

	/*
	 * Make sure the keys we have and want are in the cache.
	 */
	config.dbbackend->cached_getkeysigs(fullhave);
	config.dbbackend->cached_getkeysigs(fullwant);

	if ((keyinfoa = findinhash(fullhave)) == NULL) {
		return 1;
	}
	if ((keyinfob = findinhash(fullwant)) == NULL) {
		return 1;
	}
	
	while ((!cleanup()) && (pathlen < count)) {
		/*
		 * Fill the tree info up.
		 */
		initcolour(true);
		findpath(keyinfoa, keyinfob);
		keyinfob->parent = 0;
		if (keyinfoa->colour == 0) {
			pathlen = count;
		} else {
			/*
			 * Skip the first key, as the remote user will already
			 * have it
			 */
			curkey = findinhash(keyinfoa->parent);
			while (curkey != NULL && curkey->keyid != 0) {
	    			if (curkey->keyid != fullwant &&
						config.dbbackend->fetch_key(
						curkey->keyid,
						&publickey, false)) {
	      				flatten_publickey(publickey,
							&packets,
							&list_end);
					free_publickey(publickey);
					publickey = NULL;
				}
				if (curkey != keyinfoa && curkey != keyinfob) {
					curkey->disabled = true;
				}
				curkey = findinhash(curkey->parent);
			}
		}
		pathlen++;
	}

	/*
	 * Add the destination key to the list of returned keys.
	 */
	if (config.dbbackend->fetch_key(fullwant, &publickey, false)) {
		flatten_publickey(publickey,
				&packets,
				&list_end);
		free_publickey(publickey);
		publickey = NULL;
	}

	armor_openpgp_stream(stdout_putchar, NULL, packets);
	free_packet_list(packets);
	packets = list_end = NULL;

	return 0;
}

int main(int argc, char *argv[])
{
	char     **cgiparams = NULL;	/* Our CGI parameter block */
	uint64_t   from = 0, to = 0;
	int        op = OP_UNKNOWN;

	cgiparams = getcgivars(argc, argv);


	op = parsecgistuff(cgiparams, &from, &to);
	
	if (op != OP_GET) {
		start_html("Experimental PGP key path finder results");
	} else {
		puts("Content-Type: text/plain\n");
	}

	if (from == 0 || to == 0) {
		printf("Must pass from & to\n");
		puts("</HTML>");
		exit(1);
	}

	if (op != OP_GET) {
		printf("<P>Looking for path from 0x%016" PRIX64" to 0x%016"
				PRIX64 ".\n",
				from, to);
		printf("<A HREF=\"gpgwww?from=0x%016" PRIX64 "&to=0x%016" PRIX64
				"\">Find reverse path</A>\n",
				to,
				from);
		printf("<A HREF=\"gpgwww?from=0x%08" PRIX64 "&to=0x%08" PRIX64
				"&op=get\">"
				"Get all keys listed</A></P>\n",
				from,
				to);
	}

	readconfig(NULL);
	initlogthing("gpgwww", config.logfile);
	catchsignals();
	config.dbbackend->initdb(true);
	inithash();
	logthing(LOGTHING_NOTICE, "Looking for path from 0x%016" PRIX64
			" to 0x%016"
			PRIX64,
			from,
			to);
	if (op == OP_GET) {
		getkeyspath(from, to, 3);
	} else {
		dofindpath(from, to, true, 3);
	}
	destroyhash();
	config.dbbackend->cleanupdb();
	cleanuplogthing();
	cleanupconfig();

	if (op != OP_GET) {
		puts("<HR>");
		puts("Produced by gpgwww " ONAK_VERSION ", part of onak. ");
		end_html();
	}

	cleanupcgi(cgiparams);
	cgiparams = NULL;

	return EXIT_SUCCESS;
}
