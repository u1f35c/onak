/*
 * keymerge.c - Takes a key on stdin, merges it and outputs the difference.
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

	dearmor_openpgp_stream(stdin_getchar, NULL, &packets);
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
		flatten_publickey(keys, &packets, &list_end);
		free_publickey(keys);
		keys = NULL;

		armor_openpgp_stream(stdout_putchar, NULL, packets);
		free_packet_list(packets);
		packets = NULL;
	} else {
		rc = 1;
		fprintf(stderr, "No changes.\n");
	}

	return rc;
}
