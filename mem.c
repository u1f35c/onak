/*
 * mem.c - Routines to cleanup memory after use.
 *
 * Copyright 2002-2004,2007 Jonathan McDowell <noodles@earth.li>
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
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keystructs.h"
#include "ll.h"
#include "mem.h"
#include "stats.h"

/**
 *	packet_dup - duplicate an OpenPGP packet.
 *	@packet: The packet to duplicate.
 *
 *	This function takes an OpenPGP packet structure and duplicates it,
 *	including the data part. It returns NULL if there is a problem
 *	allocating memory for the duplicate.
 */
struct openpgp_packet *packet_dup(struct openpgp_packet *packet)
{
	struct openpgp_packet *newpacket = NULL;

	if (packet == NULL)
		return NULL;

	newpacket = malloc(sizeof (struct openpgp_packet));
	if (newpacket != NULL) {
		newpacket->tag = packet->tag;
		newpacket->newformat = packet->newformat;
		newpacket->length = packet->length;
		newpacket->data = malloc(newpacket->length);
		if (newpacket->data != NULL) {
			memcpy(newpacket->data, packet->data,
					newpacket->length);
		}
	}

	return newpacket;
}

/**
 *	packet_list_add - Adds an OpenPGP packet list to another.
 *	@list: The packet list to add to.
 *	@list_end: The end of the packet list to add to.
 *	@packet_list: The packet list to add.
 *
 *	This function takes an OpenPGP packet list and adds it to another list,
 *	duplicating it in the process. The list to add to need not exists to
 *	begin with, in which case the function simply duplicates the supplied
 *	list.
 */
void packet_list_add(struct openpgp_packet_list **list,
		struct openpgp_packet_list **list_end,
		struct openpgp_packet_list *packet_list)
{
	for (; packet_list != NULL; packet_list = packet_list->next) {
		ADD_PACKET_TO_LIST((*list_end),
				packet_dup(packet_list->packet));
		if (*list == NULL) {
			*list = *list_end;
		}
	}

	return;
}

/**
 *	free_packet - free the memory used by an OpenPGP packet.
 *	@packet: The packet to free.
 *
 *	Takes an OpenPGP packet structure and frees the memory used by it,
 *	including the data part.
 */
void free_packet(struct openpgp_packet *packet) {
	if (packet->data != NULL) {
		free(packet->data);
		packet->data = NULL;
	}
	free(packet);
}

/**
 *	free_packet_list - free the memory used by an OpenPGP packet list.
 *	@packet_list: The packet list to free.
 *
 *	Takes an OpenPGP packet list structure and frees the memory used by the
 *	packets in it and the linked list overhead.
 */
void free_packet_list(struct openpgp_packet_list *packet_list) {
	struct openpgp_packet_list *nextpacket = NULL;

	while (packet_list != NULL) {
		nextpacket = packet_list->next;
		if (packet_list->packet != NULL) {
			free_packet(packet_list->packet);
		}
		free(packet_list);
		packet_list = nextpacket;
	}
}

/**
 *	free_signedpacket_list - free an OpenPGP signed packet list.
 *	@signedpacket_list: The packet list to free.
 *
 *	Takes an OpenPGP signed packet list structure and frees the memory used
 *      by the packets and signatures it and the linked list overhead.
 */
void free_signedpacket_list(
		struct openpgp_signedpacket_list *signedpacket_list) {
	struct openpgp_signedpacket_list *nextpacket = NULL;

	while (signedpacket_list != NULL) {
		nextpacket = signedpacket_list->next;
		if (signedpacket_list->packet != NULL) {
			free_packet(signedpacket_list->packet);
		}
		if (signedpacket_list->sigs != NULL) {
			free_packet_list(signedpacket_list->sigs);
		}
		free(signedpacket_list);
		signedpacket_list = nextpacket;
	}
}

/**
 *	free_publickey - free an OpenPGP public key structure.
 *	@key: The key to free.
 *
 *	Takes an OpenPGP key and frees the memory used by all the structures it
 *	contains.
 */
void free_publickey(struct openpgp_publickey *key) {
	struct openpgp_publickey *nextkey = NULL;

	while (key != NULL) {
		nextkey = key->next;
		if (key->publickey != NULL) {
			free_packet(key->publickey);
			key->publickey = NULL;
		}
		if (key->sigs != NULL) {
			free_packet_list(key->sigs);
			key->sigs = NULL;
		}
		if (key->uids != NULL) {
			free_signedpacket_list(key->uids);
			key->uids = NULL;
		}
		if (key->subkeys != NULL) {
			free_signedpacket_list(key->subkeys);
			key->subkeys = NULL;
		}
		free(key);
		key = nextkey;
	}
}
