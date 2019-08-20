/*
 * sigcheck.c - routines to check OpenPGP signatures
 *
 * Copyright 2012 Jonathan McDowell <noodles@earth.li>
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

#include <stdint.h>

#include "build-config.h"
#include "decodekey.h"
#include "keyid.h"
#include "keystructs.h"
#include "log.h"
#include "openpgp.h"
#include "sigcheck.h"

#ifdef HAVE_NETTLE
#include <nettle/md5.h>
#include <nettle/ripemd160.h>
#include <nettle/sha.h>
#else
#include "md5.h"
#include "sha1.h"
#endif
#include "sha1x.h"

onak_status_t calculate_packet_sighash(struct openpgp_publickey *key,
			struct openpgp_packet *packet,
			struct openpgp_packet *sig,
			uint8_t *hashtype,
			uint8_t *hash,
			uint8_t **sighash)
{
	size_t siglen, unhashedlen;
	struct sha1_ctx sha1_context;
	struct sha1x_ctx sha1x_context;
	struct md5_ctx md5_context;
#ifdef HAVE_NETTLE
	struct ripemd160_ctx ripemd160_context;
	struct sha224_ctx sha224_context;
	struct sha256_ctx sha256_context;
	struct sha384_ctx sha384_context;
	struct sha512_ctx sha512_context;
#endif
	uint8_t keyheader[5];
	uint8_t packetheader[5];
	uint8_t trailer[10];
	uint8_t *hashdata[8];
	size_t hashlen[8];
	int chunks, i;
	uint64_t keyid;
	onak_status_t res;

	*hashtype = 0;
	*sighash = NULL;

	switch (sig->data[0]) {
	case 2:
	case 3:
		keyheader[0] = 0x99;
		keyheader[1] = key->publickey->length >> 8;
		keyheader[2] = key->publickey->length & 0xFF;
		hashdata[0] = keyheader;
		hashlen[0] = 3;
		hashdata[1] = key->publickey->data;
		hashlen[1] = key->publickey->length;
		chunks = 2;

		*hashtype = sig->data[16];

		if (packet != NULL) {
			if (packet->tag == OPENPGP_PACKET_PUBLICSUBKEY) {
				packetheader[0] = 0x99;
				packetheader[1] = packet->length >> 8;
				packetheader[2] = packet->length & 0xFF;
				hashdata[chunks] = packetheader;
				hashlen[chunks] = 3;
				chunks++;
			}

			// TODO: Things other than UIDS/subkeys?
			hashdata[chunks] = packet->data;
			hashlen[chunks] = packet->length;
			chunks++;
		}

		hashdata[chunks] = &sig->data[2];
		hashlen[chunks] = 5;
		chunks++;
		*sighash = &sig->data[17];
		break;
	case 4:
		keyheader[0] = 0x99;
		keyheader[1] = key->publickey->length >> 8;
		keyheader[2] = key->publickey->length & 0xFF;
		hashdata[0] = keyheader;
		hashlen[0] = 3;
		hashdata[1] = key->publickey->data;
		hashlen[1] = key->publickey->length;
		chunks = 2;

		/* Check to see if this is an X509 based signature */
		if (sig->data[2] == 0 || sig->data[2] == 100) {
			size_t len;

			keyid = 0;
			res = parse_subpackets(&sig->data[4],
						sig->length - 4, &len,
						&keyid, NULL);
			if (res != ONAK_E_OK) {
				return res;
			}
			if (keyid == 0 &&
					/* No unhashed data */
					sig->data[4 + len] == 0 &&
					sig->data[5 + len] == 0 &&
					/* Dummy 0 checksum */
					sig->data[6 + len] == 0 &&
					sig->data[7 + len] == 0 &&
					/* Dummy MPI of 1 */
					sig->data[8 + len] == 0 &&
					sig->data[9 + len] == 1 &&
					sig->data[10 + len] == 1) {
				return ONAK_E_UNSUPPORTED_FEATURE;
			}
		}

		*hashtype = sig->data[3];

		if (packet != NULL) {
			if (packet->tag == OPENPGP_PACKET_PUBLICSUBKEY) {
				packetheader[0] = 0x99;
				packetheader[1] = packet->length >> 8;
				packetheader[2] = packet->length & 0xFF;
				hashdata[chunks] = packetheader;
				hashlen[chunks] = 3;
				chunks++;
			} else if (packet->tag == OPENPGP_PACKET_UID ||
					packet->tag == OPENPGP_PACKET_UAT) {
				packetheader[0] = (packet->tag ==
					OPENPGP_PACKET_UID) ?  0xB4 : 0xD1;
				packetheader[1] = packet->length >> 24;
				packetheader[2] = (packet->length >> 16) & 0xFF;
				packetheader[3] = (packet->length >> 8) & 0xFF;
				packetheader[4] = packet->length & 0xFF;
				hashdata[chunks] = packetheader;
				hashlen[chunks] = 5;
				chunks++;
			}
			hashdata[chunks] = packet->data;
			hashlen[chunks] = packet->length;
			chunks++;
		}

		hashdata[chunks] = sig->data;
		hashlen[chunks] = siglen = (sig->data[4] << 8) +
			sig->data[5] + 6;;
		if (siglen > sig->length) {
			/* Signature data exceed packet length, bogus */
			return ONAK_E_INVALID_PKT;
		}
		chunks++;

		trailer[0] = 4;
		trailer[1] = 0xFF;
		trailer[2] = siglen >> 24;
		trailer[3] = (siglen >> 16) & 0xFF;
		trailer[4] = (siglen >> 8) & 0xFF;
		trailer[5] = siglen & 0xFF;
		hashdata[chunks] = trailer;
		hashlen[chunks] = 6;
		chunks++;

		unhashedlen = (sig->data[siglen] << 8) +
			sig->data[siglen + 1];
		*sighash = &sig->data[siglen + unhashedlen + 2];
		break;
	case 5:
		keyheader[0] = 0x9A;
		keyheader[1] = 0;
		keyheader[2] = 0;
		keyheader[3] = key->publickey->length >> 8;
		keyheader[4] = key->publickey->length & 0xFF;
		hashdata[0] = keyheader;
		hashlen[0] = 5;
		hashdata[1] = key->publickey->data;
		hashlen[1] = key->publickey->length;
		chunks = 2;

		*hashtype = sig->data[3];

		if (packet != NULL) {
			if (packet->tag == OPENPGP_PACKET_PUBLICSUBKEY) {
				packetheader[0] = 0x9A;
				packetheader[1] = 0;
				packetheader[2] = 0;
				packetheader[3] = packet->length >> 8;
				packetheader[4] = packet->length & 0xFF;
				hashdata[chunks] = packetheader;
				hashlen[chunks] = 5;
				chunks++;
			} else if (packet->tag == OPENPGP_PACKET_UID ||
					packet->tag == OPENPGP_PACKET_UAT) {
				packetheader[0] = (packet->tag ==
					OPENPGP_PACKET_UID) ?  0xB4 : 0xD1;
				packetheader[1] = packet->length >> 24;
				packetheader[2] = (packet->length >> 16) & 0xFF;
				packetheader[3] = (packet->length >> 8) & 0xFF;
				packetheader[4] = packet->length & 0xFF;
				hashdata[chunks] = packetheader;
				hashlen[chunks] = 5;
				chunks++;
			}
			hashdata[chunks] = packet->data;
			hashlen[chunks] = packet->length;
			chunks++;
		}

		hashdata[chunks] = sig->data;
		hashlen[chunks] = siglen = (sig->data[4] << 8) +
			sig->data[5] + 6;;
		if (siglen > sig->length) {
			/* Signature data exceed packet length, bogus */
			return ONAK_E_INVALID_PKT;
		}
		chunks++;

		trailer[0] = 5;
		trailer[1] = 0xFF;
		trailer[2] = 0;
		trailer[3] = 0;
		trailer[4] = 0;
		trailer[5] = 0;
		trailer[6] = siglen >> 24;
		trailer[7] = (siglen >> 16) & 0xFF;
		trailer[8] = (siglen >> 8) & 0xFF;
		trailer[9] = siglen & 0xFF;
		hashdata[chunks] = trailer;
		hashlen[chunks] = 10;
		chunks++;

		unhashedlen = (sig->data[siglen] << 8) +
			sig->data[siglen + 1];
		*sighash = &sig->data[siglen + unhashedlen + 2];
		break;
	default:
		return ONAK_E_UNSUPPORTED_FEATURE;
	}

	switch (*hashtype) {
	case OPENPGP_HASH_MD5:
		md5_init(&md5_context);
		for (i = 0; i < chunks; i++) {
			md5_update(&md5_context, hashlen[i], hashdata[i]);
		}
		md5_digest(&md5_context, MD5_DIGEST_SIZE, hash);
		break;
	case OPENPGP_HASH_SHA1:
		sha1_init(&sha1_context);
		for (i = 0; i < chunks; i++) {
			sha1_update(&sha1_context, hashlen[i], hashdata[i]);
		}
		sha1_digest(&sha1_context, SHA1_DIGEST_SIZE, hash);
		break;
	case OPENPGP_HASH_SHA1X:
		sha1x_init(&sha1x_context);
		for (i = 0; i < chunks; i++) {
			sha1x_update(&sha1x_context, hashlen[i], hashdata[i]);
		}
		sha1x_digest(&sha1x_context, SHA1X_DIGEST_SIZE, hash);
		break;
#ifdef HAVE_NETTLE
	case OPENPGP_HASH_RIPEMD160:
		ripemd160_init(&ripemd160_context);
		for (i = 0; i < chunks; i++) {
			ripemd160_update(&ripemd160_context, hashlen[i],
				hashdata[i]);
		}
		ripemd160_digest(&ripemd160_context, RIPEMD160_DIGEST_SIZE,
			hash);
		break;
	case OPENPGP_HASH_SHA224:
		sha224_init(&sha224_context);
		for (i = 0; i < chunks; i++) {
			sha224_update(&sha224_context, hashlen[i],
				hashdata[i]);
		}
		sha224_digest(&sha224_context, SHA224_DIGEST_SIZE, hash);
		break;
	case OPENPGP_HASH_SHA256:
		sha256_init(&sha256_context);
		for (i = 0; i < chunks; i++) {
			sha256_update(&sha256_context, hashlen[i],
				hashdata[i]);
		}
		sha256_digest(&sha256_context, SHA256_DIGEST_SIZE, hash);
		break;
	case OPENPGP_HASH_SHA384:
		sha384_init(&sha384_context);
		for (i = 0; i < chunks; i++) {
			sha384_update(&sha384_context, hashlen[i],
				hashdata[i]);
		}
		sha384_digest(&sha384_context, SHA384_DIGEST_SIZE, hash);
		break;
	case OPENPGP_HASH_SHA512:
		sha512_init(&sha512_context);
		for (i = 0; i < chunks; i++) {
			sha512_update(&sha512_context, hashlen[i],
				hashdata[i]);
		}
		sha512_digest(&sha512_context, SHA512_DIGEST_SIZE, hash);
		break;
#endif
	default:
		return ONAK_E_UNSUPPORTED_FEATURE;
	}

	return ONAK_E_OK;
}
