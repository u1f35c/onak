/*
 * mem.h - Routines to cleanup memory after use.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 *
 * $Id: mem.h,v 1.4 2003/06/04 20:57:11 noodles Exp $
 */

#ifndef __MEM_H_
#define __MEM_H_

#include "keystructs.h"

/**
 *	packet_dup - duplicate an OpenPGP packet.
 *	@packet: The packet to duplicate.
 *
 *	This function takes an OpenPGP packet structure and duplicates it,
 *	including the data part. It returns NULL if there is a problem
 *	allocating memory for the duplicate.
 */
struct openpgp_packet *packet_dup(struct openpgp_packet *packet);

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
		struct openpgp_packet_list *packet_list);

/**
 *	free_packet - free the memory used by an OpenPGP packet.
 *	@packet: The packet to free.
 *
 *	Takes an OpenPGP packet structure and frees the memory used by it,
 *	including the data part.
 */
void free_packet(struct openpgp_packet *packet);

/**
 *	free_packet_list - free the memory used by an OpenPGP packet list.
 *	@packet_list: The packet list to free.
 *
 *	Takes an OpenPGP packet list structure and frees the memory used by the
 *	packets in it and the linked list overhead.
 */
void free_packet_list(struct openpgp_packet_list *packet_list);

/**
 *	free_signedpacket_list - free an OpenPGP signed packet list.
 *	@signedpacket_list: The packet list to free.
 *
 *	Takes an OpenPGP signed packet list structure and frees the memory used
 *      by the packets and signatures it and the linked list overhead.
 */
void free_signedpacket_list(
		struct openpgp_signedpacket_list *signedpacket_list);

/**
 *	free_publickey - free an OpenPGP public key structure.
 *	@key: The key to free.
 *
 *	Takes an OpenPGP key and frees the memory used by all the structures it
 *	contains.
 */
void free_publickey(struct openpgp_publickey *key);

/**
 *	free_statskey - free an stats key structure.
 *	@key: The key to free.
 *
 *	Takes a stats key and frees the memory used by it and the linked list
 *	of sigs under it. Doesn't recurse into the list as it's assumed all the
 *	objects referenced also exist in the hash.
 */
void free_statskey(struct stats_key *key);

#endif /* __MEM_H_ */
