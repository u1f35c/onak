/*
 * sendsync.c - Routines to send a key sync mail.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 1999, 2002 Project Purple
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "armor.h"
#include "keystructs.h"
#include "ll.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"
#include "sendsync.h"

int fd_putchar(void *ctx, size_t count, unsigned char *c)
{
	int i;

	for (i = 0; i < count; i++) {
		fputc(c[i], ctx);
	}
	return 0;
}

/**
 *	sendkeysync - Send a key sync mail to our peers.
 *	keys: The list of keys to send.
 *
 *	Takes a list of keys and sends out a keysync mail to all our peers.
 */
int sendkeysync(struct openpgp_publickey *keys)
{
	FILE                       *fd = NULL;
	struct ll                  *cursite = NULL;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;

	if (config.syncsites != NULL &&
			(fd=popen(config.mta, "w")) != NULL) {
		fprintf(fd, "From: %s\n", config.adminemail);

		fprintf(fd, "To: ");
		for (cursite = config.syncsites; cursite != NULL;
				cursite = cursite->next) {
			fprintf(fd, "%s", (char *) cursite->object);
			if (cursite->next != NULL) {
				fprintf(fd, ", ");
			}
		}
		fprintf(fd, "\n");

		fprintf(fd, "Subject: incremental\n");
		fprintf(fd, "X-Keyserver-Sent: %s\n", config.thissite);
		fprintf(fd, "Precedence: list\n");
		fprintf(fd, "MIME-Version: 1.0\n");
		fprintf(fd, "Content-Type: application/pgp-keys\n\n");

		flatten_publickey(keys,
				&packets,
				&list_end);
		armor_openpgp_stream(fd_putchar,
				fd,
				packets);
		free_packet_list(packets);
		packets = NULL;

		pclose(fd);
	} else return 0;

	return 1;
}
