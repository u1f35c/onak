/*
 * merge.h - Routines to merge OpenPGP public keys.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 *
 * $Id: merge.h,v 1.6 2004/05/31 14:16:49 noodles Exp $
 */

#ifndef __MERGE_H__

#include "keystructs.h"

/**
 *	merge_keys - Takes 2 public keys and merges them.
 *	@a: The old key. The merged key is returned in this structure.
 *	@b: The new key. The changed from old to new keys are returned in this
 *		structure.
 *
 *	This function takes 2 keys and merges them. It then returns the merged
 *	key in a and the difference between this new key and the original a
 *	in b (ie newb contains the minimum amount of detail necessary to
 *	convert olda to newa). The intention is that olda is provided from
 *	internal storage and oldb from the remote user. newa is then stored in
 *	internal storage and newb is sent to all our keysync peers.
 */
int merge_keys(struct openpgp_publickey *a, struct openpgp_publickey *b);

/**
 *	update_keys - Takes a list of public keys and updates them in the DB.
 *	@keys: The keys to update in the DB.
 *
 *	Takes a list of keys and adds them to the database, merging them with
 *	the key in the database if it's already present there. The key list is
 *	update to contain the minimum set of updates required to get from what
 *	we had before to what we have now (ie the set of data that was added to
 *	the DB). Returns the number of entirely new keys added.
 */
int update_keys(struct openpgp_publickey **keys);

/**
 *	get_signed_packet - Gets a signed packet from a list.
 *	@packet_list: The list of packets to look in.
 *	@packet: The packet to look for.
 *
 *	Walks through the signedpacket_list looking for the supplied packet and
 *	returns it if found. Otherwise returns NULL.
 */
struct openpgp_signedpacket_list *find_signed_packet(
		struct openpgp_signedpacket_list *packet_list,
		struct openpgp_packet *packet);

/**
 *	merge_packet_sigs - Takes 2 signed packets and merges their sigs.
 *	@old: The old signed packet.
 *	@new: The new signed packet.
 *
 *	Takes 2 signed packet list structures and the sigs of the packets on
 *	the head of these structures. These packets must both be the same and
 *	the fully merged structure is returned in old and the minimal
 *	difference to get from old to new in new.
 */
int merge_packet_sigs(struct openpgp_signedpacket_list *old,
			struct openpgp_signedpacket_list *new);

#endif
