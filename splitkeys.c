/*
 * splitkeys.c - Split a keyring into smaller chunks.
 *
 * Jonathan McDowell <noodles@earth.li>
 * 
 * Copyright 2003 Project Purple
 *
 * $Id: splitkeys.c,v 1.1 2003/09/30 21:16:14 noodles Exp $
 */

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "charfuncs.h"
#include "keystructs.h"
#include "mem.h"
#include "parsekey.h"

int main(int argc, char *argv[])
{
	struct openpgp_packet_list	*packets = NULL;
	struct openpgp_packet_list	*list_end = NULL;
	struct openpgp_packet_list	*tmp = NULL;
	int				 result = 0;
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
			exit(1);
		}
	}

	do {
		result = read_openpgp_stream(stdin_getchar, NULL,
				 &packets, maxkeys);
		if (packets != NULL) {
			list_end = packets;
			while (list_end->next != NULL) {
				tmp = list_end;
				list_end = list_end->next;
				if (list_end->next == NULL &&
					list_end->packet->tag == 6) {
					tmp->next = NULL;
				}
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
