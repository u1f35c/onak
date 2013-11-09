/*
 * keyid.c - Routines to calculate key IDs.
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

#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "config.h"
#include "keyid.h"
#include "keystructs.h"
#include "onak.h"
#include "parsekey.h"
#include "mem.h"
#include "merge.h"

#ifdef HAVE_NETTLE
#include <nettle/md5.h>
#include <nettle/ripemd160.h>
#include <nettle/sha.h>
#else
#include "md5.h"
#include "sha1.h"
#endif


/**
 *	get_keyid - Given a public key returns the keyid.
 *	@publickey: The key to calculate the id for.
 */
onak_status_t get_keyid(struct openpgp_publickey *publickey, uint64_t *keyid)
{
	return (get_packetid(publickey->publickey, keyid));
}

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
onak_status_t get_fingerprint(struct openpgp_packet *packet,
	struct openpgp_fingerprint *fingerprint)
{
	struct sha1_ctx sha_ctx;
	struct md5_ctx md5_context;
	unsigned char c;
	size_t         modlen, explen;

	if (fingerprint == NULL)
		return ONAK_E_INVALID_PARAM;

	fingerprint->length = 0;

	switch (packet->data[0]) {
	case 2:
	case 3:
		md5_init(&md5_context);

		/*
		 * MD5 the modulus and exponent.
		 */
		modlen = ((packet->data[8] << 8) +
			 packet->data[9] + 7) >> 3;
		md5_update(&md5_context, modlen, &packet->data[10]);

		explen = ((packet->data[10+modlen] << 8) +
			 packet->data[11+modlen] + 7) >> 3;
		md5_update(&md5_context, explen, &packet->data[12 + modlen]);

		fingerprint->length = 16;
		md5_digest(&md5_context, fingerprint->length, fingerprint->fp);

		break;

	case 4:
		sha1_init(&sha_ctx);
		/*
		 * TODO: Can this be 0x99? Are all public key packets old
		 * format with 2 bytes of length data?
		 */
		c = 0x99;
		sha1_update(&sha_ctx, sizeof(c), &c);
		c = packet->length >> 8;
		sha1_update(&sha_ctx, sizeof(c), &c);
		c = packet->length & 0xFF;
		sha1_update(&sha_ctx, sizeof(c), &c);
		sha1_update(&sha_ctx, packet->length,
			packet->data);
		fingerprint->length = 20;
		sha1_digest(&sha_ctx, fingerprint->length, fingerprint->fp);

		break;
	default:
		return ONAK_E_UNKNOWN_VER;
	}

	return ONAK_E_OK;
}


/**
 *	get_packetid - Given a PGP packet returns the keyid.
 *	@packet: The packet to calculate the id for.
 */
onak_status_t get_packetid(struct openpgp_packet *packet, uint64_t *keyid)
{
	int		offset = 0;
	int		i = 0;
	struct openpgp_fingerprint fingerprint;
#ifdef NETTLE_WITH_RIPEMD160
	struct ripemd160_ctx ripemd160_context;
	uint8_t		data;
#endif

	if (packet == NULL)
		return ONAK_E_INVALID_PARAM;

	switch (packet->data[0]) {
	case 2:
	case 3:
		/*
		 * Old versions of GnuPG would put Elgamal keys inside
		 * a V3 key structure, then generate the keyid using
		 * RIPED160.
		 */
#ifdef NETTLE_WITH_RIPEMD160
		if (packet->data[7] == 16) {
			ripemd160_init(&ripemd160_context);
			data = 0x99;
			ripemd160_update(&ripemd160_context, 1, &data);
			data = packet->length >> 8;
			ripemd160_update(&ripemd160_context, 1, &data);
			data = packet->length & 0xFF;
			ripemd160_update(&ripemd160_context, 1, &data);
			ripemd160_update(&ripemd160_context,
				packet->length,
				packet->data);

			ripemd160_digest(&ripemd160_context,
				RIPEMD160_DIGEST_SIZE,
				fingerprint.fp);

			for (*keyid = 0, i = 12; i < 20; i++) {
				*keyid <<= 8;
				*keyid += fingerprint.fp[i];
			}

			return ONAK_E_OK;
		}
#endif
		/*
		 * Check for an RSA key; if not return an error.
		 * 1 == RSA
		 * 2 == RSA Encrypt-Only
		 * 3 == RSA Sign-Only
		 */
		if (packet->data[7] < 1 || packet->data[7] > 3) {
			return ONAK_E_INVALID_PKT;
		}

		/*
		 * For a type 2 or 3 key the keyid is the last 64 bits of the
		 * public modulus n, which is stored as an MPI from offset 8
		 * onwards.
		 */
		offset = (packet->data[8] << 8) +
			packet->data[9];
		offset = ((offset + 7) / 8) + 2;

		for (*keyid = 0, i = 0; i < 8; i++) {
			*keyid <<= 8;
			*keyid += packet->data[offset++];
		}
		break;
	case 4:
		get_fingerprint(packet, &fingerprint);
		
		for (*keyid = 0, i = 12; i < 20; i++) {
			*keyid <<= 8;
			*keyid += fingerprint.fp[i];
		}

		break;
	default:
		return ONAK_E_UNKNOWN_VER;
	}

	return ONAK_E_OK;
}

static struct openpgp_packet_list *sortpackets(struct openpgp_packet_list
							*packets)
{
	struct openpgp_packet_list *sorted, **cur, *next;

	sorted = NULL;
	while (packets != NULL) {
		cur = &sorted;
		while (*cur != NULL && compare_packets((*cur)->packet,
				packets->packet) < 0) {
			cur = &((*cur)->next);
		}
		next = *cur;
		*cur = packets;
		packets = packets->next;
		(*cur)->next = next;
	}

	return sorted;
}

onak_status_t get_skshash(struct openpgp_publickey *key, struct skshash *hash)
{
	struct openpgp_packet_list *packets = NULL, *list_end = NULL;
	struct openpgp_packet_list *curpacket;
	struct md5_ctx md5_context;
	struct openpgp_publickey *next;
	uint32_t tmp;

	/*
	 * We only want a single key, so clear any link to the next
	 * one for the period during the flatten.
	 */
	next = key->next;
	key->next = NULL;
	flatten_publickey(key, &packets, &list_end);
	key->next = next;
	packets = sortpackets(packets);

	md5_init(&md5_context);

	for (curpacket = packets; curpacket != NULL;
			curpacket = curpacket->next) {
		tmp = htonl(curpacket->packet->tag);
		md5_update(&md5_context, sizeof(tmp), (void *) &tmp);
		tmp = htonl(curpacket->packet->length);
		md5_update(&md5_context, sizeof(tmp), (void *) &tmp);
		md5_update(&md5_context,
				curpacket->packet->length,
				curpacket->packet->data);
	}

	md5_digest(&md5_context, 16, (uint8_t *) &hash->hash);
	free_packet_list(packets);

	return ONAK_E_OK;
}

uint8_t hexdigit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else
		return 0;
}

int parse_skshash(char *search, struct skshash *hash)
{
	int i, len;

	len = strlen(search);
	if (len > 32) {
		return 0;
	}

	for (i = 0; i < len; i += 2) {
		hash->hash[i >> 1] = (hexdigit(search[i]) << 4) +
				hexdigit(search[i + 1]);
	}

	return 1;
}
