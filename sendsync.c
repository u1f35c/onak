/*
 * sendsync.c - Routines to send a key sync mail.
 *
 * Copyright 1999, 2002, 2005, 2011 Jonathan McDowell <noodles@earth.li>
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

int fd_putchar(void *ctx, size_t count, void *c)
{
	fwrite(c, sizeof(char), count, ctx);

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
