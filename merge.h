/*
 * merge.h - Routines to merge OpenPGP public keys.
 *
 * Copyright 2002-2005,2007,2011 Jonathan McDowell <noodles@earth.li>
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

#ifndef __MERGE_H__

#include "keystructs.h"

/**
 *	compare_packets - Check to see if 2 OpenPGP packets are the same.
 *	@a: The first packet to compare.
 *	@b: The second packet to compare.
 *
 *	Takes 2 packets and returns 0 if they are the same, -1 if a is
 *      less than b, or 1 if a is greater than b.
 */
int compare_packets(struct openpgp_packet *a, struct openpgp_packet *b);

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
 *	find_packet - Checks to see if an OpenPGP packet exists in a list.
 *	@packet_list: The list of packets to look in.
 *	@packet: The packet to look for.
 *
 *	Walks through the packet_list checking to see if the packet given is
 *	present in it. Returns true if it is.
 */
bool find_packet(struct openpgp_packet_list *packet_list,
			struct openpgp_packet *packet);

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
