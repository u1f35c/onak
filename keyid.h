/*
 * keyid.h - Routines to calculate key IDs.
 *
 * Copyright 2002,2011 Jonathan McDowell <noodles@earth.li>
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

#ifndef __KEYID_H__
#define __KEYID_H__

#include <inttypes.h>

#include "keystructs.h"
#include "onak.h"

/**
 *	get_keyid - Given a public key returns the keyid.
 *	@publickey: The key to calculate the id for.
 *	@keeyid: The returned keyid
 *
 *	This function returns the key id for a given public key.
 */
onak_status_t get_keyid(struct openpgp_publickey *publickey, uint64_t *keyid);

/**
 *	get_fingerprint - Given a public key returns the fingerprint.
 *	@publickey: The key to calculate the id for.
 *	@fingerprint: The fingerprint structure to store the result in
 *
 *	This function returns the fingerprint for a given public key. As Type 3
 *	fingerprints are 16 bytes and Type 4 are 20 the len field indicates
 *	which we've returned.
 */
onak_status_t get_fingerprint(struct openpgp_packet *packet,
	struct openpgp_fingerprint *fingerprint);

/**
 *	get_packetid - Given a PGP packet returns the keyid.
 *	@packet: The packet to calculate the id for.
 *	@keyid: The returned keyid
 *
 *	This function returns the key id for a given PGP packet.
 */
onak_status_t get_packetid(struct openpgp_packet *packet, uint64_t *keyid);

/**
 *	get_skshash - Given a public key returns the SKS hash for it.
 *	@publickey: The key to calculate the hash for.
 *	@skshash: Hash structure to sort the result in.
 *
 *	This function returns the SKS hash for a given public key. This
 *	is an MD5 hash over a sorted list of all of the packets that
 *	make up the key. The caller should allocate the memory for the
 *	hash.
 */
onak_status_t get_skshash(struct openpgp_publickey *publickey,
	struct skshash *hash);

/**
 *	parse_skshash - Parse a string into an SKS hash structure.
 *	@search: The string representing the SKS hash.
 *	@hash: A pointer to the structure to store the hash in.
 *
 *	Takes a string and tries to parse it as an SKS hash hex
 *	representation. Puts the hash into the supplied structure
 *	if successful. Returns 1 if we parsed something ok, 0 if
 *	we failed.
 */
int parse_skshash(char *search, struct skshash *hash);

#endif /* __KEYID_H__ */
