/*
 * gpgwww.c - www interface to path finder.
 * 
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2001-2002 Project Purple.
 */

// #include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "getcgi.h"
#include "hash.h"
#include "keydb.h"
#include "stats.h"

void dofindpath(uint64_t have, uint64_t want, bool html)
{
	struct stats_key *keyinfoa, *keyinfob, *curkey;
	int rec;
	char *uid;

	/*
	 * Make sure the keys we have and want are in the cache.
	 */
	hash_getkeysigs(have);
	hash_getkeysigs(want);

	if ((keyinfoa = findinhash(have)) == NULL) {
		printf("Couldn't find key 0x%llX.\n", have);
		return;
	}
	if ((keyinfob = findinhash(want)) == NULL) {
		printf("Couldn't find key 0x%llX.\n", want);
		return;
	}
	
	/*
	 * Fill the tree info up.
	 */
	initcolour(true);
	rec = findpath(keyinfoa, keyinfob);
	keyinfob->parent = 0;

	printf("%d nodes examined. %ld elements in the hash\n", rec,
			hashelements());
	if (keyinfoa->colour == 0) {
		printf("Can't find a link from 0x%llX to 0x%llX\n",
				have,
				want);
	} else {
		printf("%d steps from 0x%llX to 0x%llX\n",
				keyinfoa->colour, have, want);
		curkey = keyinfoa;
		while (curkey != NULL && curkey->keyid != 0) {
			uid = keyid2uid(curkey->keyid);
			if (html && uid == NULL) {
				printf("<a href=\"lookup?op=get&search=%llX\">"
					"0x%llX</a> ([User id not found])%s)%s\n",
					curkey->keyid,
					curkey->keyid,
					(curkey->keyid == want) ? "" :
					 " signs");
			} else if (html && uid != NULL) {
				printf("<a href=\"lookup?op=get&search=%llX\">"
					"0x%llX</a> (<a href=\"lookup?op=vindex"
					"&search=0x%llX\">%s</a>)%s\n",
					curkey->keyid,
					curkey->keyid,
					curkey->keyid,
					txt2html(keyid2uid(curkey->keyid)),
					(curkey->keyid == want) ? "" :
					 " signs");
			} else {
				printf("0x%llX (%s)%s\n",
					curkey->keyid,
					(uid == NULL) ? "[User id not found]" :
						uid,
					(curkey->keyid == want) ? "" :
					 " signs");
			}
			curkey = findinhash(curkey->parent);
		}
	}
}

void parsecgistuff(char **cgiparams, uint64_t *from, uint64_t *to)
{
	int i = 0;

	if (cgiparams != NULL) {
		i = 0;
		while (cgiparams[i] != NULL) {
			if (!strcmp(cgiparams[i], "to")) {
				*to = strtoul(cgiparams[i+1], NULL, 16);
			} else if (!strcmp(cgiparams[i], "from")) {
				*from = strtoul(cgiparams[i+1], NULL, 16);
			}
			i += 2;
		}
	}

	return;
}

int main(int argc, char *argv[])
{
	char **cgiparams = NULL;	/* Our CGI parameter block */
	uint64_t from = 0, to = 0;

	cgiparams = getcgivars(argc, argv);

	puts("Content-Type: text/html\n");
	puts("<HTML>");
	puts("<HEAD>");
	puts("<TITLE>Experimental PGP key path finder results</TITLE>");
	puts("</HEAD>");
	puts("<BODY>");
	puts("</BODY>");

	parsecgistuff(cgiparams, &from, &to);

	if (from == 0 || to == 0) {
		printf("Must pass from & to\n");
		puts("</HTML>");
		exit(1);
	}

	printf("<P>Looking for path from 0x%llX to 0x%llX</P>\n", from, to);
	puts("<PRE>");
	initdb();
	inithash();
	dofindpath(from, to, true);
	cleanupdb();
	puts("</PRE>");

	puts("<HR>");
	puts("Produced by gpgwww 0.0.1, part of onak. <A HREF=\"mailto:noodles-onak@earth.li\">Jonathan McDowell</A>");
	puts("</HTML>");

	return EXIT_SUCCESS;
}
