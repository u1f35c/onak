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

struct cgi_get_ctx {
	char *buffer;
	int offset;
};


int cgi_getchar(void *ctx, unsigned char *c)
{
	struct cgi_get_ctx *buf = NULL;

	buf = (struct cgi_get_ctx *) ctx;

	*c = buf->buffer[buf->offset++];

	return (*c == 0);
}

int main(int argc, char *argv[])
{
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_publickey *keys = NULL;
	struct openpgp_publickey *curkey = NULL;
	char **params = NULL;
	struct cgi_get_ctx ctx;
	int i;

	memset(&ctx, 0, sizeof(ctx));

	params = getcgivars(argc, argv);
	for (i = 0; params != NULL && params[i] != NULL; i += 2) {
		if (!strcmp(params[i], "keytext")) {
			ctx.buffer = params[i+1];
		}
	}

//	puts("HTTP/1.0 200 OK");
//	puts("Server: onak 0.0.1");
	puts("Content-Type: text/html\n");
	puts("<html><title>onak : Add</title><body>");
	if (ctx.buffer == NULL) {
		puts("Error: No keytext to add supplied.");
	} else {
		dearmor_openpgp_stream(cgi_getchar,
					&ctx,
					&packets);
		if (packets != NULL) {
			parse_keys(packets, &keys);
			curkey = keys;
			initdb();
			while (curkey != NULL) {
				if (store_key(curkey)) {
//					puts("Key added successfully.");
				} else {
					printf("Problem adding key '%s'.\n", strerror(errno));
				}
				curkey = curkey->next;
			}
			cleanupdb();
			puts("Keys added.");
		} else {
			puts("No OpenPGP packets found in input.");
		}
	}
	puts("</body></html>");
	return (EXIT_SUCCESS);
}
