/*
 * add.c - CGI to add keys.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "armor.h"
#include "charfuncs.h"
#include "getcgi.h"
#include "keydb.h"
#include "keystructs.h"
#include "mem.h"
#include "merge.h"
#include "onak-conf.h"
#include "parsekey.h"
#include "sendsync.h"

int main(int argc, char *argv[])
{
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_publickey *keys = NULL;
	char **params = NULL;
	struct buffer_ctx ctx;
	int i;

	memset(&ctx, 0, sizeof(ctx));

	params = getcgivars(argc, argv);
	for (i = 0; params != NULL && params[i] != NULL; i += 2) {
		if (!strcmp(params[i], "keytext")) {
			ctx.buffer = params[i+1];
			ctx.size = strlen(ctx.buffer);
		} else {
			free(params[i+1]);
		}
		params[i+1] = NULL;
		free(params[i]);
		params[i] = NULL;
	}
	if (params != NULL) {
		free(params);
		params = NULL;
	}

	start_html("onak : Add");
	if (ctx.buffer == NULL) {
		puts("Error: No keytext to add supplied.");
	} else {
		dearmor_openpgp_stream(buffer_fetchchar,
					&ctx,
					&packets);
		if (packets != NULL) {
			parse_keys(packets, &keys);
			readconfig();
			initdb();
			printf("Got %d new keys.\n",
					update_keys(&keys, false));
			if (keys != NULL) {
				sendkeysync(keys);
				free_publickey(keys);
				keys = NULL;
			}
			cleanupdb();
		} else {
			puts("No OpenPGP packets found in input.");
		}
	}
	end_html();
	return (EXIT_SUCCESS);
}
