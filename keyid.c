/*
 * keyid.c - Routines to calculate key IDs.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 *
 * $Id: keyid.c,v 1.10 2004/05/31 22:04:51 noodles Exp $
 */

#include <sys/types.h>

#include "assert.h"
#include "keyid.h"
#include "keystructs.h"
#include "log.h"
#include "md5.h"
#include "sha1.h"


/**
 *	get_keyid - Given a public key returns the keyid.
 *	@publickey: The key to calculate the id for.
 */
uint64_t get_keyid(struct openpgp_publickey *publickey)
{
	return (get_packetid(publickey->publickey));
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
unsigned char *get_fingerprint(struct openpgp_packet *packet,
	unsigned char *fingerprint,
	size_t *len)
{
	SHA1_CTX sha_ctx;
	struct md5_ctx md5_context;
	unsigned char c;
	size_t         modlen, explen;

	assert(fingerprint != NULL);
	assert(len != NULL);

	*len = 0;

	switch (packet->data[0]) {
	case 2:
	case 3:
		md5_init_ctx(&md5_context);

		/*
		 * MD5 the modulus and exponent.
		 */
		modlen = ((packet->data[8] << 8) +
			 packet->data[9] + 7) >> 3;
		md5_process_bytes(&packet->data[10], modlen, &md5_context);

		explen = ((packet->data[10+modlen] << 8) +
			 packet->data[11+modlen] + 7) >> 3;
		md5_process_bytes(&packet->data[12 + modlen], explen,
				&md5_context);

		md5_finish_ctx(&md5_context, fingerprint);
		*len = 16;

		break;

	case 4:
		SHA1Init(&sha_ctx);
		/*
		 * TODO: Can this be 0x99? Are all public key packets old
		 * format with 2 bytes of length data?
		 */
		c = 0x99;
		SHA1Update(&sha_ctx, &c, sizeof(c));
		c = packet->length >> 8;
		SHA1Update(&sha_ctx, &c, sizeof(c));
		c = packet->length & 0xFF;
		SHA1Update(&sha_ctx, &c, sizeof(c));
		SHA1Update(&sha_ctx, packet->data,
			packet->length);
		SHA1Final(fingerprint, &sha_ctx);
		*len = 20;

		break;
	default:
		logthing(LOGTHING_ERROR, "Unknown key type: %d",
				packet->data[0]);
	}

	return fingerprint;
}


/**
 *	get_packetid - Given a PGP packet returns the keyid.
 *	@packet: The packet to calculate the id for.
 */
uint64_t get_packetid(struct openpgp_packet *packet)
{
	uint64_t	keyid = 0;
	int		offset = 0;
	int		i = 0;
	size_t		length = 0;
	unsigned char	buff[20];

	assert(packet != NULL);

	switch (packet->data[0]) {
	case 2:
	case 3:
		/*
		 * For a type 2 or 3 key the keyid is the last 64 bits of the
		 * public modulus n, which is stored as an MPI from offset 8
		 * onwards.
		 */
		offset = (packet->data[8] << 8) +
			packet->data[9];
		offset = ((offset + 7) / 8) + 2;

		for (keyid = 0, i = 0; i < 8; i++) {
			keyid <<= 8;
			keyid += packet->data[offset++];
		}
		/*
		 * Check for an RSA key; if not then log but accept anyway.
		 * 1 == RSA
		 * 2 == RSA Encrypt-Only
		 * 3 == RSA Sign-Only
		 */
		if (packet->data[7] < 1 || packet->data[7] > 3) {
			logthing(LOGTHING_NOTICE,
				"Type 2 or 3 key, but not RSA: %llx (type %d)",
				keyid,
				packet->data[7]);
		}
		break;
	case 4:
		get_fingerprint(packet, buff, &length);
		
		for (keyid = 0, i = 12; i < 20; i++) {
			keyid <<= 8;
			keyid += buff[i];
		}

		break;
	default:
		logthing(LOGTHING_ERROR, "Unknown key type: %d",
				packet->data[0]);
	}

	return keyid;
}
