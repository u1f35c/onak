/*
 * gpgwww.c - www interface to path finder.
 * 
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2001-2002 Project Purple.
 *
 * $Id: gpgwww.c,v 1.11 2003/06/08 19:04:31 noodles Exp $
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "getcgi.h"
#include "hash.h"
#include "keydb.h"
#include "log.h"
#include "onak-conf.h"
#include "stats.h"

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

	start_html("Experimental PGP key path finder results");

	parsecgistuff(cgiparams, &from, &to);

	if (from == 0 || to == 0) {
		printf("Must pass from & to\n");
		puts("</HTML>");
		exit(1);
	}

	printf("<P>Looking for path from 0x%llX to 0x%llX.\n", from, to);
	printf("<A HREF=\"gpgwww?from=0x%08llX&to=0x%08llX\">"
			"Find reverse path</A></P>\n",
			to,
			from);

	readconfig();
	initlogthing("gpgwww", config.logfile);
	initdb();
	inithash();
	dofindpath(from, to, true, 3);
	destroyhash();
	cleanupdb();
	cleanuplogthing();
	cleanupconfig();

	puts("<HR>");
	puts("Produced by gpgwww " VERSION ", part of onak. "
		"<A HREF=\"mailto:noodles-onak@earth.li\">"
		"Jonathan McDowell</A>");
	end_html();

	cleanupcgi(cgiparams);
	cgiparams = NULL;

	return EXIT_SUCCESS;
}
