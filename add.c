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
#include "getcgi.h"
#include "keydb.h"
#include "keystructs.h"
#include "parsekey.h"
#include "merge.h"

struct cgi_get_ctx {
	char *buffer;
	int offset;
};


int cgi_getchar(void *ctx, size_t count, unsigned char *c)
{
	struct cgi_get_ctx *buf = NULL;

	buf = (struct cgi_get_ctx *) ctx;

	while (count-- > 0 && *c != 0) {
		*c = buf->buffer[buf->offset++];
	}

	return (*c == 0);
}

int main(int argc, char *argv[])
{
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_publickey *keys = NULL;
	char **params = NULL;
	struct cgi_get_ctx ctx;
	int i;

	memset(&ctx, 0, sizeof(ctx));

	params = getcgivars(argc, argv);
	for (i = 0; params != NULL && params[i] != NULL; i += 2) {
		if (!strcmp(params[i], "keytext")) {
			ctx.buffer = params[i+1];
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
		dearmor_openpgp_stream(cgi_getchar,
					&ctx,
					&packets);
		if (packets != NULL) {
			parse_keys(packets, &keys);
			initdb();
			printf("Got %d new keys.\n",
					update_keys(&keys, false));
			cleanupdb();
		} else {
			puts("No OpenPGP packets found in input.");
		}
	}
	end_html();
	return (EXIT_SUCCESS);
}
