/*
 * keyindex.h - Routines to list an OpenPGP key.
 *
 * Copyright 2002-2008 Jonathan McDowell <noodles@earth.li>
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

#ifndef __DECODEKEY_H__
#define __DECODEKEY_H__

#include <inttypes.h>
#include <time.h>
#include "keystructs.h"
#include "ll.h"

/**
 *	keysigs - Return the sigs on a given OpenPGP signature packet list.
 *	@curll: The current linked list. Can be NULL to create a new list.
 *	@sigs: The signature list we want the sigs on.
 *
 *	Returns a linked list of stats_key elements containing the sigs for the
 *	supplied OpenPGP signature packet list.
 */
struct ll *keysigs(struct ll *curll,
		struct openpgp_packet_list *sigs);

/**
 *	sig_info - Get info on a given OpenPGP signature packet
 *	@packet: The signature packet
 *	@keyid: A pointer for where to return the signature keyid
 *	@creation: A pointer for where to return the signature creation time
 *
 *	Gets any info about a signature packet; parses the subpackets for a v4
 *	key or pulls the data directly from v2/3. NULL can be passed for any
 *	values which aren't cared about.
 */
void sig_info(struct openpgp_packet *packet, uint64_t *keyid, time_t *creation);

/**
 *	sig_keyid - Return the keyid for a given OpenPGP signature packet.
 *	@packet: The signature packet.
 *
 *	Returns the keyid for the supplied signature packet.
 */
uint64_t sig_keyid(struct openpgp_packet *packet);

/**
 *	keyuids - Takes a key and returns an array of its UIDs
 *	@key: The key to get the uids of.
 *	@primary: A pointer to store the primary UID in.
 *
 *	keyuids takes a public key structure and builds an array of the UIDs 
 *	on the key. It also attempts to work out the primary UID and returns a
 *	separate pointer to that particular element of the array.
 */
char **keyuids(struct openpgp_publickey *key, char **primary);

/**
 *	keysubkeys - Takes a key & returns an array of its subkey fingerprints
 *	@key: The key to get the subkeys of.
 *
 *	keysubkeys takes a public key structure and returns an array of the
 *	subkey fingerprints for that key.
 */
struct openpgp_fingerprint *keysubkeys(struct openpgp_publickey *key);

/**
 *	parse_subpackets - Parse the subpackets of a Type 4 signature.
 *	@data: The subpacket data.
 *	@keyid: A pointer to where we should return the keyid.
 *	@creationtime: A pointer to where we should return the creation time.
 *
 *	This function parses the subkey data of a Type 4 signature and fills
 *	in the supplied variables. It also returns the length of the data
 *	processed. If the value of any piece of data is not desired a NULL
 *	can be passed instead of a pointer to a storage area for that value.
 */
int parse_subpackets(unsigned char *data, uint64_t *keyid, time_t *creation);

#endif
