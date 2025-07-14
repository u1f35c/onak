/**
 * @file keystructs.h
 * @brief Structures for OpenPGP keys
 *
 * Copyright 2002 Jonathan McDowell <noodles@earth.li>
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

#ifndef __KEYSTRUCTS_H__
#define __KEYSTRUCTS_H__

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include "ll.h"

/*
 * Fingerprint lengths
 *
 * v3 MD5 fingerprint is 16 bytes
 * v4 SHA-1 fingerprint is 20
 * v5 SHA2-256 fingerprint is 32
 * v6 SHA2-256 fingerprint is 32
 */
#define FINGERPRINT_V3_LEN	16
#define FINGERPRINT_V4_LEN	20
#define FINGERPRINT_V5_LEN	32
#define FINGERPRINT_V6_LEN	32
#define MAX_FINGERPRINT_LEN	32

/**
 * @brief Stores the fingerprint of an OpenPGP key
 */
struct openpgp_fingerprint {
	/** Length of fingerprint. 16 bytes for v3, 20 for v4 */
	size_t length;
	/** Fingerprint data. Only the first length bytes are valid */
	uint8_t fp[MAX_FINGERPRINT_LEN];
};

/**
 * @brief Stores an OpenPGP packet.
 *
 * This structure holds any form of OpenPGP packet with minimum common
 * details decoded out.
 */
struct openpgp_packet {
	/** The packet tag (i.e. type). */
	unsigned int tag;
	/** Indicates if this is a new format packet. */
	bool newformat;
	/** The length of the packet. */
	size_t length;
	/** The actual packet data. */
	unsigned char *data;
};

/**
 * @brief A linked list of OpenPGP packets.
 *
 * This structure is used to hold a linked list of packets, for example
 * all the signatures of a public key's UID.
 */
struct openpgp_packet_list {
	/** The actual packet structure. */
	struct openpgp_packet *packet;
	/** A pointer to the next packet in the list. */
	struct openpgp_packet_list *next;
};

/**
 * @brief A packet with signatures.
 *
 * This structure holds an OpenPGP packet along with signatures that are
 * over this packet. It also links to the next signed packet. It's usually
 * used to hold a UID or subkey with their associated signatures.
 */
struct openpgp_signedpacket_list {
	/** The OpenPGP packet that's signed. */
	struct openpgp_packet *packet;
	/** A linked list of sigs for the packet. */
	struct openpgp_packet_list *sigs;
	/** Pointer to the last sig in the sigs linked list */
	struct openpgp_packet_list *last_sig;
	/** A pointer to the next packet with signatures. */
	struct openpgp_signedpacket_list *next;
};

/**
 * @brief An OpenPGP public key complete with sigs.
 */
struct openpgp_publickey {
	/** The OpenPGP packet for the public key. */
	struct openpgp_packet			*publickey;
	/** True if the key is revoked. */
	bool					 revoked;
	/** Any signatures directly on the @a publickey packet. */
	struct openpgp_packet_list		*sigs;
	/** Pointer to the end of the @a sigs list */
	struct openpgp_packet_list		*last_sig;
	/** The list of UIDs with signatures for this key. */
	struct openpgp_signedpacket_list	*uids;
	/** Pointer to the end of the @a uids list */
	struct openpgp_signedpacket_list	*last_uid;
	/** The list of subkeys with signatures for this key. */
	struct openpgp_signedpacket_list	*subkeys;
	/** Pointer to the end of the @a subkey list */
	struct openpgp_signedpacket_list	*last_subkey;
	/** The next public key. */
	struct openpgp_publickey		*next;
};

/**
 * @brief Holds an SKS key hash (md5 over sorted packet list)
 */
struct skshash {
	/** The 128 bit MD5 hash of the sorted packet list from the key */
	uint8_t hash[16];
};

#endif /* __KEYSTRUCTS_H__ */
