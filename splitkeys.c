/*
 * splitkeys.c - Split a keyring into smaller chunks.
 *
 * Copyright 2003 Jonathan McDowell <noodles@earth.li>
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

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "charfuncs.h"
#include "keystructs.h"
#include "mem.h"
#include "openpgp.h"
#include "parsekey.h"

int main(int argc, char *argv[])
{
	struct openpgp_packet_list	*packets = NULL;
	struct openpgp_packet_list	*list_end = NULL;
	struct openpgp_packet_list	*tmp = NULL;
	int				 maxkeys = 10000;
	int				 outfd = -1;
	int				 count = 0;
	char				 splitfile[1024];

	if (argc > 1) {
		maxkeys = atoi(argv[1]);
		if (maxkeys == 0) {
			fprintf(stderr,
				"Couldn't parse %s as a number of keys!\n",
				argv[1]);
			exit(EXIT_FAILURE);
		}
	}

	do {
		read_openpgp_stream(stdin_getchar, NULL,
				 &packets, maxkeys);
		if (packets != NULL) {
			list_end = packets;
			while (list_end->next != NULL) {
				tmp = list_end;
				list_end = list_end->next;
				if (list_end->next == NULL &&
					list_end->packet->tag ==
						OPENPGP_PACKET_PUBLICKEY) {
					tmp->next = NULL;
				}
			}
			if (tmp->next != NULL) {
				list_end = NULL;
			}

			snprintf(splitfile, 1023, "splitfile-%d.pgp", count);
			outfd = open(splitfile, O_WRONLY | O_CREAT, 0664);
			write_openpgp_stream(file_putchar, &outfd,
					packets);
			close(outfd);
			free_packet_list(packets);
			packets = list_end;
			count++;
		}
	} while (packets != NULL);

	return 0;
}
