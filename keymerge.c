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

int stdin_getchar(void *ctx, unsigned char *c)
{
	int ic;
	ic = getchar();
	*c = ic;
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
	struct openpgp_publickey	*prev = NULL;
	struct openpgp_publickey	*curkey = NULL;
	struct openpgp_publickey	*oldkey = NULL;
	int				 newkeys = 0;
	int				 rc = EXIT_SUCCESS;

	dearmor_openpgp_stream(stdin_getchar, NULL, &packets);
	parse_keys(packets, &keys);
	free_packet_list(packets);
	packets = NULL;

	initdb();
	for (curkey = keys; curkey != NULL; curkey = curkey->next) {
		fprintf(stderr, "Dealing with key.\n");
		fprintf(stderr, "fetch_key: %d\n",
				fetch_key(get_keyid(curkey), &oldkey));

		/*
		 * If we already have the key stored in the DB then merge it
		 * with the new one that's been supplied. Otherwise the key
		 * we've just got is the one that goes in the DB and also the
		 * one that we send out.
		 */
		if (oldkey != NULL) {
			fprintf(stderr, "merge_keys: %d\n",
					merge_keys(oldkey, curkey));
			if (curkey->revocations == NULL &&
					curkey->uids == NULL &&
					curkey->subkeys == NULL) {
				fprintf(stderr, "No new info.\n");
				if (prev == NULL) {
					keys = curkey->next;
				} else {
					prev->next = curkey->next;
					prev = curkey->next;
				}
			} else {
				prev = curkey;
			}
			/* TODO: store_key(oldkey); */
			free_publickey(oldkey);
			oldkey = NULL;
		} else {
			store_key(curkey);
			newkeys++;
		}
	}
	cleanupdb();

	if (keys != NULL) {
		flatten_publickey(keys, &packets, &list_end);
		free_publickey(keys);
		keys = NULL;

		armor_openpgp_stream(stdout_putchar, NULL, packets);
		free_packet_list(packets);
		packets = NULL;
	} else {
		rc = 1;
	}

	return rc;
}
