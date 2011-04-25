/*
 * keyid.h - Routines to calculate key IDs.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#ifndef __KEYID_H__
#define __KEYID_H__

#include <inttypes.h>

#include "keystructs.h"

/**
 *	get_keyid - Given a public key returns the keyid.
 *	@publickey: The key to calculate the id for.
 *
 *	This function returns the key id for a given public key.
 */
uint64_t get_keyid(struct openpgp_publickey *publickey);

/**
 *	get_fingerprint - Given a public key returns the fingerprint.
 *	@publickey: The key to calculate the id for.
 *	@fingerprint: The fingerprint (must be at least 20 bytes of space). 
 *	@len: The length of the returned fingerprint.
 *
 *	This function returns the fingerprint for a given public key. As Type 3
 *	fingerprints are 16 bytes and Type 4 are 20 the len field indicates
 *	which we've returned.
 */
unsigned char *get_fingerprint(struct openpgp_packet *packet,
	unsigned char *fingerprint,
	size_t *len);

/**
 *	get_packetid - Given a PGP packet returns the keyid.
 *	@packet: The packet to calculate the id for.
 *
 *	This function returns the key id for a given PGP packet.
 */
uint64_t get_packetid(struct openpgp_packet *packet);

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
void get_skshash(struct openpgp_publickey *publickey, struct skshash *hash);

#endif /* __KEYID_H__ */
