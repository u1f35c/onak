/*
 * keyid.c - Routines to calculate key IDs.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#include <sys/types.h>

#include "keyid.h"
#include "keystructs.h"
#include "md5.h"
#include "sha.h"

/**
 *	get_keyid - Given a public key returns the keyid.
 *	@publickey: The key to calculate the fingerprint for.
 */
uint64_t get_keyid(struct openpgp_publickey *publickey)
{
	SHA1_CONTEXT sha_ctx;
	uint64_t keyid = 0;
	int offset = 0;
	int i = 0;
	unsigned char c;
	unsigned char *buff = NULL;

	switch (publickey->publickey->data[0]) {
	case 2:
	case 3:
		/*
		 * For a type 2 or 3 key the keyid is the last 64 bits of the
		 * public modulus n, which is stored as an MPI from offset 8
		 * onwards.
		 *
		 * We need to ensure it's an RSA key.
		 */
		if (publickey->publickey->data[7] == 1) {
			offset = (publickey->publickey->data[8] << 8) +
				publickey->publickey->data[9];
			offset = ((offset + 7) / 8) + 2;

			for (keyid = 0, i = 0; i < 8; i++) {
				keyid <<= 8;
				keyid += publickey->publickey->data[offset++];
			}
		} else {
			fputs("Type 2 or 3 key, but not RSA.\n", stderr);
		}
		break;
	case 4:
		/*
		 * For a type 4 key the keyid is the last 64 bits of the
		 * fingerprint, which is the 160 bit SHA-1 hash of the packet
		 * tag, 2 octet packet length and the public key packet
		 * including version field.
		 */
		sha1_init(&sha_ctx);
		/*
		 * TODO: Can this be 0x99? Are all public key packets old
		 * format with 2 bytes of length data?
		 */
		c = 0x99;
		sha1_write(&sha_ctx, &c, sizeof(c));
		c = publickey->publickey->length >> 8;
		sha1_write(&sha_ctx, &c, sizeof(c));
		c = publickey->publickey->length & 0xFF;
		sha1_write(&sha_ctx, &c, sizeof(c));
		sha1_write(&sha_ctx, publickey->publickey->data,
			publickey->publickey->length);
		sha1_final(&sha_ctx);
		buff = sha1_read(&sha_ctx);

		assert(buff != NULL);
		
		for (keyid = 0, i = 12; i < 20; i++) {
			keyid <<= 8;
			keyid += buff[i];
		}

		break;
	default:
		printf("Unknown key type: %d\n", publickey->publickey->data[0]);
	}

	return keyid;
}
