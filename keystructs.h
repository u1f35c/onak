/*
 * keystructs.h - Structures for OpenPGP keys
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#ifndef __KEYSTRUCTS_H__
#define __KEYSTRUCTS_H__

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include "ll.h"

/**
 *	struct openpgp_packet - Stores an OpenPGP packet.
 *	@tag: The packet tag (ie type).
 *	@newformat: Indicates if this is a new format packet.
 *	@length: The length of the packet.
 *	@data: The actual packet
 *
 *	This structure holds any form of OpenPGP packet with minimum common
 *	details decoded out.
 */
struct openpgp_packet {
	unsigned int tag;
	bool newformat;
	size_t length;
	unsigned char *data;
};

/**
 *	struct openpgp_packet_list - A linked list of OpenPGP packets.
 *	@packet: The actual packet structure.
 *	@next: A pointer to the next packet in the list.
 *
 *	This structure is used to hold a linked list of packets, for example
 *	all the signatures of a public key's UID.
 */
struct openpgp_packet_list {
	struct openpgp_packet *packet;
	struct openpgp_packet_list *next;
};

/**
 *	struct openpgp_signedpacket_list - A packet with signatures.
 *	@uid: The OpenPGP packet that's signed.
 *	@sigs: A list of sigs for the packet.
 *	@next: A pointer to the next packet with signatures.
 *
 *	This structure holds an OpenPGP packet along with signatures that are
 *	over this packet. It also links to the next signed packet. It's usually
 *	used to hold a UID or subkey with their associated signatures.
 */
struct openpgp_signedpacket_list {
	struct openpgp_packet *packet;
	struct openpgp_packet_list *sigs;
	struct openpgp_packet_list *last_sig;
	struct openpgp_signedpacket_list *next;
};

/**
 *	struct openpgp_publickey - An OpenPGP public key complete with sigs.
 *	@publickey: The OpenPGP packet for the public key.
 *	@revocation: The OpenPGP packet for the revocation [optional]
 *	@uids: The list of UIDs with signatures for this key.
 *	@subkeys: The list of subkeys with signatures for this key.
 *	@next: The next public key.
 */
struct openpgp_publickey {
	struct openpgp_packet			*publickey;
	struct openpgp_packet_list		*revocations;
	struct openpgp_packet_list		*last_revocation;
	struct openpgp_signedpacket_list	*uids;
	struct openpgp_signedpacket_list	*last_uid;
	struct openpgp_signedpacket_list	*subkeys;
	struct openpgp_signedpacket_list	*last_subkey;
	struct openpgp_publickey		*next;
};

/**
 *	struct stats_key - holds key details suitable for doing stats on.
 *	@keyid: The keyid.
 *	@colour: Used for marking during DFS/BFS.
 *	@parent: The key that lead us to this one for DFS/BFS.
 *	@sigs: A linked list of the signatures on this key.
 *	@gotsigs: A bool indicating if we've initialized the sigs element yet.
 */
struct stats_key {
	uint64_t keyid;
	int colour;
	uint64_t parent;
	struct ll *sigs;
	bool gotsigs;
};

#endif /* __KEYSTRUCTS_H__ */
