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

#include "armor.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "mem.h"
#include "merge.h"
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

int stdout_putchar(void *ctx, unsigned char c)
{
	return (putchar(c));
}


int main(int argc, char *argv[])
{
	struct openpgp_packet_list	*packets = NULL;
	struct openpgp_packet_list	*list_end = NULL;
	struct openpgp_publickey	*keys = NULL;
	int				 rc = EXIT_SUCCESS;

	read_openpgp_stream(stdin_getchar, NULL, &packets);
	if (packets != NULL) {
		parse_keys(packets, &keys);
		free_packet_list(packets);
		packets = NULL;

		initdb();
		fprintf(stderr, "Got %d new keys.\n",
				update_keys(&keys));
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

	return rc;
}
