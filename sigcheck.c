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
#include <string.h>

#include "build-config.h"
#include "decodekey.h"
#include "hash-helper.h"
#include "keyid.h"
#include "keystructs.h"
#include "log.h"
#include "onak.h"
#include "openpgp.h"
#include "sigcheck.h"

#ifdef HAVE_CRYPTO
#include <gmp.h>
#include <nettle/dsa.h>
#include <nettle/ecc.h>
#include <nettle/ecc-curve.h>
#include <nettle/ecdsa.h>
#include <nettle/eddsa.h>
#include <nettle/rsa.h>
#include "rsa.h"

#ifndef HAVE_NETTLE_GET_SECP_256R1
#define nettle_get_secp_256r1() &nettle_secp_256r1
#endif
#ifndef HAVE_NETTLE_GET_SECP_384R1
#define nettle_get_secp_384r1() &nettle_secp_384r1
#endif
#ifndef HAVE_NETTLE_GET_SECP_521R1
#define nettle_get_secp_521r1() &nettle_secp_521r1
#endif

#endif

/* Take an MPI from a buffer and import it into a GMP mpz_t */
#define MPI_TO_MPZ(pk, v) \
{                                                                             \
	/* MPI length is stored in bits, convert it to bytes */               \
	if (pk->length < (ofs + 2)) {                                         \
		ret = ONAK_E_INVALID_PKT;                                     \
	} else {                                                              \
		len = pk->data[ofs] << 8 | pk->data[ofs + 1];                 \
		len += 7;                                                     \
		len = len >> 3;                                               \
		if (pk->length < (ofs + len + 2)) {                           \
			ret = ONAK_E_INVALID_PKT;                             \
		} else {                                                      \
			mpz_import(v, len, 1, 1, 0, 0, &pk->data[ofs + 2]);   \
			ofs += len + 2;                                       \
		}                                                             \
	}                                                                     \
}

#if HAVE_CRYPTO

/*
 * Hold the crypto material for a public key.
 * May want to move to a header at some point.
 */
struct onak_key_material {
	uint8_t type;
	union {
		struct dsa_params dsa;
		struct ecc_point ecc;
		struct rsa_public_key rsa;
		uint8_t ed25519[32];
	};
	mpz_t y;
};

static void onak_free_key_material(struct onak_key_material *key)
{
	switch (key->type) {
	case OPENPGP_PKALGO_ECDSA:
		ecc_point_clear(&key->ecc);
		break;
	case OPENPGP_PKALGO_DSA:
		mpz_clear(key->dsa.p);
		mpz_clear(key->dsa.q);
		mpz_clear(key->dsa.g);
		mpz_clear(key->y);
		break;
	case OPENPGP_PKALGO_RSA:
	case OPENPGP_PKALGO_RSA_ENC:
	case OPENPGP_PKALGO_RSA_SIGN:
		mpz_clear(key->rsa.n);
		mpz_clear(key->rsa.e);
		break;
	}

	/* Set the key type back to 0 to indicate we cleared it */
	key->type = 0;

	return;
}

static onak_status_t onak_parse_key_material(struct openpgp_packet *pk,
		struct onak_key_material *key)
{
	int i, len, ofs;
	enum onak_oid oid;
	mpz_t x, y;
	onak_status_t ret = ONAK_E_OK;

	/* Clear the key type; only set it when fully parsed */
	key->type = 0;

	/*
	 * Shortest valid key is v4 Ed25519, which takes 51 bytes, so do a
	 * quick sanity check which will ensure we have enough data to check
	 * the packet header and OID info.
	 */
	if (pk->length < 51)
		return ONAK_E_INVALID_PKT;

	if (pk->data[0] != 4 && pk->data[0] != 5)
		return ONAK_E_UNSUPPORTED_FEATURE;

	/*
	 * MPIs are after version byte, 4 byte creation time +
	 * type byte plus length for v5.
	 */
	ofs = (pk->data[0] == 4) ? 6 : 10;
	switch (pk->data[5]) {
	case OPENPGP_PKALGO_ECDSA:
		oid = onak_parse_oid(&pk->data[ofs], pk->length - ofs);
		if (oid == ONAK_OID_INVALID)
			return ONAK_E_INVALID_PKT;
		if (oid == ONAK_OID_UNKNOWN)
			return ONAK_E_UNSUPPORTED_FEATURE;

		if (oid == ONAK_OID_NISTP256) {
			if (pk->length - ofs != 76)
				return ONAK_E_INVALID_PKT;
			/* Move past the OID to the key data MPI */
			ofs += pk->data[ofs] + 1;
			len = pk->data[ofs] << 8 | pk->data[ofs + 1];
			if (len != 515)
				return ONAK_E_INVALID_PKT;
			if (pk->data[ofs + 2] != 4)
				return ONAK_E_INVALID_PKT;
			mpz_init(x);
			mpz_init(y);
			ecc_point_init(&key->ecc, nettle_get_secp_256r1());
			ofs += 3;
			mpz_import(x, 32, 1, 1, 0, 0, &pk->data[ofs]);
			ofs += 32;
			mpz_import(y, 32, 1, 1, 0, 0, &pk->data[ofs]);
			ofs += 32;
			ecc_point_set(&key->ecc, x, y);
		} else if (oid == ONAK_OID_NISTP384) {
			if (pk->length - ofs != 105)
				return ONAK_E_INVALID_PKT;
			/* Move past the OID to the key data MPI */
			ofs += pk->data[ofs] + 1;
			len = pk->data[ofs] << 8 | pk->data[ofs + 1];
			if (len != 771)
				return ONAK_E_INVALID_PKT;
			if (pk->data[ofs + 2] != 4)
				return ONAK_E_INVALID_PKT;
			mpz_init(x);
			mpz_init(y);
			ecc_point_init(&key->ecc, nettle_get_secp_384r1());
			ofs += 3;
			mpz_import(x, 48, 1, 1, 0, 0, &pk->data[ofs]);
			ofs += 48;
			mpz_import(y, 48, 1, 1, 0, 0, &pk->data[ofs]);
			ofs += 48;
			ecc_point_set(&key->ecc, x, y);
		} else if (oid == ONAK_OID_NISTP521) {
			if (pk->length - ofs != 141)
				return ONAK_E_INVALID_PKT;
			/* Move past the OID to the key data MPI */
			ofs += pk->data[ofs] + 1;
			len = pk->data[ofs] << 8 | pk->data[ofs + 1];
			if (len != 1059)
				return ONAK_E_INVALID_PKT;
			if (pk->data[ofs + 2] != 4)
				return ONAK_E_INVALID_PKT;
			mpz_init(x);
			mpz_init(y);
			ecc_point_init(&key->ecc, nettle_get_secp_521r1());
			ofs += 3;
			mpz_import(x, 66, 1, 1, 0, 0, &pk->data[ofs]);
			ofs += 66;
			mpz_import(y, 66, 1, 1, 0, 0, &pk->data[ofs]);
			ofs += 66;
			ecc_point_set(&key->ecc, x, y);
		} else {
			return ONAK_E_UNSUPPORTED_FEATURE;
		}
		mpz_clear(y);
		mpz_clear(x);
		break;
	case OPENPGP_PKALGO_EDDSA:
		if (pk->length - ofs != 45)
			return ONAK_E_INVALID_PKT;
		oid = onak_parse_oid(&pk->data[ofs], pk->length - ofs);
		if (oid == ONAK_OID_INVALID)
			return ONAK_E_INVALID_PKT;
		if (oid == ONAK_OID_UNKNOWN)
			return ONAK_E_UNSUPPORTED_FEATURE;

		/* Move past the OID to the key data MPI */
		ofs += pk->data[ofs] + 1;

		if (oid == ONAK_OID_ED25519) {
			len = pk->data[ofs] << 8 | pk->data[ofs + 1];
			if (len != 263)
				return ONAK_E_INVALID_PKT;
			if (pk->data[ofs + 2] != 0x40)
				return ONAK_E_INVALID_PKT;
			ofs += 3;
			memcpy(key->ed25519, &pk->data[ofs], 32);
			ofs += 32;
		} else {
			return ONAK_E_UNSUPPORTED_FEATURE;
		}
		break;
	case OPENPGP_PKALGO_DSA:
		mpz_init(key->dsa.p);
		mpz_init(key->dsa.q);
		mpz_init(key->dsa.g);
		mpz_init(key->y);
		MPI_TO_MPZ(pk, key->dsa.p);
		if (ret == ONAK_E_OK)
			MPI_TO_MPZ(pk, key->dsa.q);
		if (ret == ONAK_E_OK)
			MPI_TO_MPZ(pk, key->dsa.g);
		if (ret == ONAK_E_OK)
			MPI_TO_MPZ(pk, key->y);
		break;
	case OPENPGP_PKALGO_RSA:
	case OPENPGP_PKALGO_RSA_ENC:
	case OPENPGP_PKALGO_RSA_SIGN:
		mpz_init(key->rsa.n);
		mpz_init(key->rsa.e);
		key->rsa.size = ((pk->data[6] << 8) + pk->data[7] + 7) >> 3;
		MPI_TO_MPZ(pk, key->rsa.n);
		if (ret == ONAK_E_OK)
			MPI_TO_MPZ(pk, key->rsa.e);
		break;
	default:
		return ONAK_E_UNSUPPORTED_FEATURE;
	}

	/*
	 * Keep scan-build happy; we bump this in MPI_TO_MPZ and then don't use
	 * it again the last time we do so.
	 */
	(void)ofs;

	key->type = pk->data[5];

	if (ret != ONAK_E_OK) {
		onak_free_key_material(key);
	}

	return ret;
}

onak_status_t onak_check_hash_sig(struct openpgp_publickey *sigkey,
		struct openpgp_packet *sig,
		uint8_t *hash,
		uint8_t hashtype)
{
	onak_status_t ret;
	struct onak_key_material pubkey;
	struct dsa_signature dsasig;
	uint8_t sigkeytype;
	uint8_t edsig[64];
	uint64_t keyid;
	int len, ofs;
	mpz_t s;

	ret = onak_parse_key_material(sigkey->publickey, &pubkey);
	if (ret != ONAK_E_OK) {
		return ret;
	}

	/* Sanity check the length of the signature packet */
	if (sig->length < 8) {
		ret = ONAK_E_INVALID_PKT;
		goto out;
	}

	if (sig->data[0] == 3) {
		/* Must be 5 bytes hashed */
		if (sig->data[1] != 5) {
			ret = ONAK_E_INVALID_PARAM;
			goto out;
		}

		/* Need at least 19 bytes for the sig header */
		if (sig->length < 19) {
			ret = ONAK_E_INVALID_PKT;
			goto out;
		}

		/* Skip to the signature material */
		ofs = 19;
		sigkeytype = sig->data[15];
	} else if (sig->data[0] >= 4) {
		/* Skip the hashed data */
		ofs = (sig->data[4] << 8) + sig->data[5] + 6;
		if (sig->length < ofs + 2) {
			ret = ONAK_E_INVALID_PKT;
			goto out;
		}
		/* Skip the unhashed data */
		ofs += (sig->data[ofs] << 8) + sig->data[ofs + 1] + 2;
		if (sig->length < ofs + 2) {
			ret = ONAK_E_INVALID_PKT;
			goto out;
		}
		/* Skip the sig hash bytes */
		ofs += 2;
		sigkeytype = sig->data[2];
	} else {
		ret = ONAK_E_UNSUPPORTED_FEATURE;
		goto out;
	}

	/* Is the key the same type as the signature we're checking? */
	if (pubkey.type != sigkeytype) {
		ret = ONAK_E_INVALID_PARAM;
		goto out;
	}

	/* Parse the actual signature values */
	switch (sigkeytype) {
	case OPENPGP_PKALGO_ECDSA:
	case OPENPGP_PKALGO_DSA:
		mpz_init(dsasig.r);
		mpz_init(dsasig.s);
		MPI_TO_MPZ(sig, dsasig.r);
		if (ret == ONAK_E_OK)
			MPI_TO_MPZ(sig, dsasig.s);
		break;
	case OPENPGP_PKALGO_EDDSA:
		mpz_init(dsasig.r);
		mpz_init(dsasig.s);
		MPI_TO_MPZ(sig, dsasig.r);
		if (ret == ONAK_E_OK)
			MPI_TO_MPZ(sig, dsasig.s);
		mpz_export(edsig, NULL, 1, 1, 0, 0, dsasig.r);
		mpz_export(&edsig[32], NULL, 1, 1, 0, 0, dsasig.s);
		break;
	case OPENPGP_PKALGO_RSA:
	case OPENPGP_PKALGO_RSA_SIGN:
		mpz_init(s);
		MPI_TO_MPZ(sig, s);
		break;
	}

	/* If we didn't parse the signature properly then do clean-up */
	if (ret != ONAK_E_OK)
		goto sigerr;

	/* Squash a signing only RSA key to a standard RSA key for below */
	if (pubkey.type == OPENPGP_PKALGO_RSA_SIGN) {
		pubkey.type = OPENPGP_PKALGO_RSA;
	}

#define KEYHASH(key, hash) ((key << 8) | hash)

	switch KEYHASH(pubkey.type, hashtype) {
	case KEYHASH(OPENPGP_PKALGO_DSA, OPENPGP_HASH_MD5):
		ret = dsa_verify(&pubkey.dsa, pubkey.y,
				MD5_DIGEST_SIZE, hash, &dsasig) ?
			ONAK_E_WEAK_SIGNATURE : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_DSA, OPENPGP_HASH_RIPEMD160):
		ret = dsa_verify(&pubkey.dsa, pubkey.y,
				RIPEMD160_DIGEST_SIZE, hash, &dsasig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_DSA, OPENPGP_HASH_SHA1):
		ret = dsa_verify(&pubkey.dsa, pubkey.y,
				SHA1_DIGEST_SIZE, hash, &dsasig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_DSA, OPENPGP_HASH_SHA1X):
		ret = dsa_verify(&pubkey.dsa, pubkey.y,
				SHA1X_DIGEST_SIZE, hash, &dsasig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_DSA, OPENPGP_HASH_SHA224):
		ret = dsa_verify(&pubkey.dsa, pubkey.y,
				SHA224_DIGEST_SIZE, hash, &dsasig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_DSA, OPENPGP_HASH_SHA256):
		ret = dsa_verify(&pubkey.dsa, pubkey.y,
				SHA256_DIGEST_SIZE, hash, &dsasig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_DSA, OPENPGP_HASH_SHA384):
		ret = dsa_verify(&pubkey.dsa, pubkey.y,
				SHA384_DIGEST_SIZE, hash, &dsasig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_DSA, OPENPGP_HASH_SHA512):
		ret = dsa_verify(&pubkey.dsa, pubkey.y,
				SHA512_DIGEST_SIZE, hash, &dsasig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_ECDSA, OPENPGP_HASH_SHA1):
		ret = ecdsa_verify(&pubkey.ecc,
				SHA1_DIGEST_SIZE, hash, &dsasig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_ECDSA, OPENPGP_HASH_SHA256):
		ret = ecdsa_verify(&pubkey.ecc,
				SHA256_DIGEST_SIZE, hash, &dsasig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_ECDSA, OPENPGP_HASH_SHA384):
		ret = ecdsa_verify(&pubkey.ecc,
				SHA384_DIGEST_SIZE, hash, &dsasig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_ECDSA, OPENPGP_HASH_SHA512):
		ret = ecdsa_verify(&pubkey.ecc,
				SHA512_DIGEST_SIZE, hash, &dsasig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_EDDSA, OPENPGP_HASH_RIPEMD160):
		ret = ed25519_sha512_verify(pubkey.ed25519,
				RIPEMD160_DIGEST_SIZE, hash, edsig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_EDDSA, OPENPGP_HASH_SHA256):
		ret = ed25519_sha512_verify(pubkey.ed25519,
				SHA256_DIGEST_SIZE, hash, edsig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_EDDSA, OPENPGP_HASH_SHA384):
		ret = ed25519_sha512_verify(pubkey.ed25519,
				SHA384_DIGEST_SIZE, hash, edsig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_EDDSA, OPENPGP_HASH_SHA512):
		ret = ed25519_sha512_verify(pubkey.ed25519,
				SHA512_DIGEST_SIZE, hash, edsig) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_RSA, OPENPGP_HASH_MD5):
		ret = rsa_md5_verify_digest(&pubkey.rsa, hash, s) ?
			ONAK_E_WEAK_SIGNATURE : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_RSA, OPENPGP_HASH_RIPEMD160):
		ret = rsa_ripemd160_verify_digest(&pubkey.rsa, hash, s) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_RSA, OPENPGP_HASH_SHA1):
		ret = rsa_sha1_verify_digest(&pubkey.rsa, hash, s) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_RSA, OPENPGP_HASH_SHA224):
		ret = rsa_sha224_verify_digest(&pubkey.rsa, hash, s) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_RSA, OPENPGP_HASH_SHA256):
		ret = rsa_sha256_verify_digest(&pubkey.rsa, hash, s) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_RSA, OPENPGP_HASH_SHA384):
		ret = rsa_sha384_verify_digest(&pubkey.rsa, hash, s) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	case KEYHASH(OPENPGP_PKALGO_RSA, OPENPGP_HASH_SHA512):
		ret = rsa_sha512_verify_digest(&pubkey.rsa, hash, s) ?
			ONAK_E_OK : ONAK_E_BAD_SIGNATURE;
		break;
	default:
		ret = ONAK_E_UNSUPPORTED_FEATURE;
	}

sigerr:
	switch (sigkeytype) {
	case OPENPGP_PKALGO_ECDSA:
	case OPENPGP_PKALGO_EDDSA:
	case OPENPGP_PKALGO_DSA:
		mpz_clear(dsasig.r);
		mpz_clear(dsasig.s);
		break;
	case OPENPGP_PKALGO_RSA:
	case OPENPGP_PKALGO_RSA_SIGN:
		mpz_clear(s);
		break;
	}

out:
	onak_free_key_material(&pubkey);

	return ret;
}

#endif /* HAVE_CRYPTO */

onak_status_t calculate_packet_sighash(struct openpgp_publickey *key,
			struct openpgp_packet *packet,
			struct openpgp_packet *sig,
			uint8_t *hashtype,
			uint8_t *hash,
			uint8_t **sighash)
{
	size_t siglen, unhashedlen;
	struct onak_hash_data hashdata;
	uint8_t keyheader[5];
	uint8_t packetheader[5];
	uint8_t trailer[10];
	int i;
	uint64_t keyid;
	onak_status_t res;

	*hashtype = 0;
	*sighash = NULL;
	memset(&hashdata, 0, sizeof(hashdata));

	switch (sig->data[0]) {
	case 2:
	case 3:
		keyheader[0] = 0x99;
		keyheader[1] = key->publickey->length >> 8;
		keyheader[2] = key->publickey->length & 0xFF;
		hashdata.data[0] = keyheader;
		hashdata.len[0] = 3;
		hashdata.data[1] = key->publickey->data;
		hashdata.len[1] = key->publickey->length;
		hashdata.chunks = 2;

		*hashtype = sig->data[16];

		if (packet != NULL) {
			if (packet->tag == OPENPGP_PACKET_PUBLICSUBKEY) {
				packetheader[0] = 0x99;
				packetheader[1] = packet->length >> 8;
				packetheader[2] = packet->length & 0xFF;
				hashdata.data[hashdata.chunks] = packetheader;
				hashdata.len[hashdata.chunks] = 3;
				hashdata.chunks++;
			}

			// TODO: Things other than UIDS/subkeys?
			hashdata.data[hashdata.chunks] = packet->data;
			hashdata.len[hashdata.chunks] = packet->length;
			hashdata.chunks++;
		}

		hashdata.data[hashdata.chunks] = &sig->data[2];
		hashdata.len[hashdata.chunks] = 5;
		hashdata.chunks++;
		*sighash = &sig->data[17];
		break;
	case 4:
		keyheader[0] = 0x99;
		keyheader[1] = key->publickey->length >> 8;
		keyheader[2] = key->publickey->length & 0xFF;
		hashdata.data[0] = keyheader;
		hashdata.len[0] = 3;
		hashdata.data[1] = key->publickey->data;
		hashdata.len[1] = key->publickey->length;
		hashdata.chunks = 2;

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
				hashdata.data[hashdata.chunks] = packetheader;
				hashdata.len[hashdata.chunks] = 3;
				hashdata.chunks++;
			} else if (packet->tag == OPENPGP_PACKET_UID ||
					packet->tag == OPENPGP_PACKET_UAT) {
				packetheader[0] = (packet->tag ==
					OPENPGP_PACKET_UID) ?  0xB4 : 0xD1;
				packetheader[1] = packet->length >> 24;
				packetheader[2] = (packet->length >> 16) & 0xFF;
				packetheader[3] = (packet->length >> 8) & 0xFF;
				packetheader[4] = packet->length & 0xFF;
				hashdata.data[hashdata.chunks] = packetheader;
				hashdata.len[hashdata.chunks] = 5;
				hashdata.chunks++;
			}
			hashdata.data[hashdata.chunks] = packet->data;
			hashdata.len[hashdata.chunks] = packet->length;
			hashdata.chunks++;
		}

		hashdata.data[hashdata.chunks] = sig->data;
		hashdata.len[hashdata.chunks] = siglen = (sig->data[4] << 8) +
			sig->data[5] + 6;;
		if (siglen > sig->length) {
			/* Signature data exceed packet length, bogus */
			return ONAK_E_INVALID_PKT;
		}
		hashdata.chunks++;

		trailer[0] = 4;
		trailer[1] = 0xFF;
		trailer[2] = siglen >> 24;
		trailer[3] = (siglen >> 16) & 0xFF;
		trailer[4] = (siglen >> 8) & 0xFF;
		trailer[5] = siglen & 0xFF;
		hashdata.data[hashdata.chunks] = trailer;
		hashdata.len[hashdata.chunks] = 6;
		hashdata.chunks++;

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
		hashdata.data[0] = keyheader;
		hashdata.len[0] = 5;
		hashdata.data[1] = key->publickey->data;
		hashdata.len[1] = key->publickey->length;
		hashdata.chunks = 2;

		*hashtype = sig->data[3];

		if (packet != NULL) {
			if (packet->tag == OPENPGP_PACKET_PUBLICSUBKEY) {
				packetheader[0] = 0x9A;
				packetheader[1] = 0;
				packetheader[2] = 0;
				packetheader[3] = packet->length >> 8;
				packetheader[4] = packet->length & 0xFF;
				hashdata.data[hashdata.chunks] = packetheader;
				hashdata.len[hashdata.chunks] = 5;
				hashdata.chunks++;
			} else if (packet->tag == OPENPGP_PACKET_UID ||
					packet->tag == OPENPGP_PACKET_UAT) {
				packetheader[0] = (packet->tag ==
					OPENPGP_PACKET_UID) ?  0xB4 : 0xD1;
				packetheader[1] = packet->length >> 24;
				packetheader[2] = (packet->length >> 16) & 0xFF;
				packetheader[3] = (packet->length >> 8) & 0xFF;
				packetheader[4] = packet->length & 0xFF;
				hashdata.data[hashdata.chunks] = packetheader;
				hashdata.len[hashdata.chunks] = 5;
				hashdata.chunks++;
			}
			hashdata.data[hashdata.chunks] = packet->data;
			hashdata.len[hashdata.chunks] = packet->length;
			hashdata.chunks++;
		}

		hashdata.data[hashdata.chunks] = sig->data;
		hashdata.len[hashdata.chunks] = siglen = (sig->data[4] << 8) +
			sig->data[5] + 6;;
		if (siglen > sig->length) {
			/* Signature data exceed packet length, bogus */
			return ONAK_E_INVALID_PKT;
		}
		hashdata.chunks++;

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
		hashdata.data[hashdata.chunks] = trailer;
		hashdata.len[hashdata.chunks] = 10;
		hashdata.chunks++;

		unhashedlen = (sig->data[siglen] << 8) +
			sig->data[siglen + 1];
		*sighash = &sig->data[siglen + unhashedlen + 2];
		break;
	default:
		return ONAK_E_UNSUPPORTED_FEATURE;
	}

	hashdata.hashtype = *hashtype;

	res = onak_hash(&hashdata, hash);

	return res;
}
