/*
 * decodekey.c - Routines to further decode an OpenPGP key.
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
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "decodekey.h"
#include "hash.h"
#include "keyid.h"
#include "keystructs.h"
#include "ll.h"
#include "openpgp.h"

/*
 *	parse_subpackets - Parse the subpackets of a Type 4 signature.
 *	@data: The subpacket data.
 *	@len: The amount of data available to read.
 *	@keyid: A pointer to where we should return the keyid.
 *	@creationtime: A pointer to where we should return the creation time.
 *
 *	This function parses the subkey data of a Type 4+ signature and fills
 *	in the supplied variables. If the value of any piece of data is not
 *	desired a NULL can be passed instead of a pointer to a storage area for
 *	that value.
 */
onak_status_t parse_subpackets(unsigned char *data, size_t length,
		uint64_t *keyid, time_t *creation)
{
	int offset = 0;
	int packetlen = 0;
	struct openpgp_fingerprint fp;
	int i;

	assert(data != NULL);

	offset = 0;
	while (offset < length) {
		packetlen = data[offset++];
		if (packetlen > 191 && packetlen < 255) {
			packetlen = ((packetlen - 192) << 8) +
					data[offset++] + 192;
		} else if (packetlen == 255) {
			packetlen = data[offset++];
			packetlen <<= 8;
			packetlen |= data[offset++];
			packetlen <<= 8;
			packetlen |= data[offset++];
			packetlen <<= 8;
			packetlen |= data[offset++];
		}
		/* Check the supplied length is within the remaining data */
		if (packetlen == 0 || (packetlen + offset) > length) {
			return ONAK_E_INVALID_PKT;
		}
		switch (data[offset] & 0x7F) {
		case OPENPGP_SIGSUB_CREATION:
			/*
			 * Signature creation time.
			 */
			if (creation != NULL) {
				*creation = data[offset + packetlen - 4];
				*creation <<= 8;
				*creation += data[offset + packetlen - 3];
				*creation <<= 8;
				*creation += data[offset + packetlen - 2];
				*creation <<= 8;
				*creation += data[offset + packetlen - 1];
			}
			break;
			/*
			 * Signature expiration time. Might want to output this?
			 */
			break;
		case OPENPGP_SIGSUB_ISSUER:
			if (keyid != NULL) {
				*keyid = data[offset+packetlen - 8];
				*keyid <<= 8;
				*keyid += data[offset+packetlen - 7];
				*keyid <<= 8;
				*keyid += data[offset+packetlen - 6];
				*keyid <<= 8;
				*keyid += data[offset+packetlen - 5];
				*keyid <<= 8;
				*keyid += data[offset+packetlen - 4];
				*keyid <<= 8;
				*keyid += data[offset+packetlen - 3];
				*keyid <<= 8;
				*keyid += data[offset+packetlen - 2];
				*keyid <<= 8;
				*keyid += data[offset+packetlen - 1];
			}
			break;
		case OPENPGP_SIGSUB_ISSUER_FINGER:
			if ((packetlen - 2) <= MAX_FINGERPRINT_LEN &&
					keyid != NULL) {
				fp.length = packetlen - 2;
				for (i = 0; i < fp.length; i++) {
					fp.fp[i] = data[offset + i + 2];
				}
				*keyid = fingerprint2keyid(&fp);
			}
			break;
		case OPENPGP_SIGSUB_EXPIRY:
		case OPENPGP_SIGSUB_EXPORTABLE:
		case OPENPGP_SIGSUB_TRUSTSIG:
		case OPENPGP_SIGSUB_REGEX:
		case OPENPGP_SIGSUB_REVOCABLE:
		case OPENPGP_SIGSUB_CAPABILITIES:
		case OPENPGP_SIGSUB_KEYEXPIRY:
		case OPENPGP_SIGSUB_ARR:
		case OPENPGP_SIGSUB_PREFSYM:
		case OPENPGP_SIGSUB_REVOCATION_KEY:
		case OPENPGP_SIGSUB_ISSUER_UID:
		case OPENPGP_SIGSUB_URL:
		case OPENPGP_SIGSUB_X_ISSUER_FINGER:
		case OPENPGP_SIGSUB_NOTATION:
		case OPENPGP_SIGSUB_PREFHASH:
		case OPENPGP_SIGSUB_PREFCOMPRESS:
		case OPENPGP_SIGSUB_KEYSERVER:
		case OPENPGP_SIGSUB_PREFKEYSERVER:
		case OPENPGP_SIGSUB_PRIMARYUID:
		case OPENPGP_SIGSUB_POLICYURI:
		case OPENPGP_SIGSUB_KEYFLAGS:
		case OPENPGP_SIGSUB_SIGNER_UID:
		case OPENPGP_SIGSUB_REVOKE_REASON:
		case OPENPGP_SIGSUB_FEATURES:
		case OPENPGP_SIGSUB_SIGNATURE_TARGET:
		case OPENPGP_SIGSUB_EMBEDDED_SIG:
			/*
			 * Various subpacket types we know about, but don't
			 * currently handle. Some are candidates for being
			 * supported if we add signature checking support.
			 */
			break;
		default:
			/*
			 * We don't care about unrecognized packets unless bit
			 * 7 is set in which case we log a major error.
			 */
			if (data[offset] & 0x80) {
				return ONAK_E_UNSUPPORTED_FEATURE;
			}
		}
		offset += packetlen;
	}

	return ONAK_E_OK;
}

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
onak_status_t sig_info(struct openpgp_packet *packet, uint64_t *keyid,
		time_t *creation)
{
	size_t offset, length = 0;
	onak_status_t res;

	if (packet != NULL) {
		switch (packet->data[0]) {
		case 2:
		case 3:
			if (keyid != NULL) {
				*keyid = packet->data[7];
				*keyid <<= 8;
				*keyid += packet->data[8];
				*keyid <<= 8;
				*keyid += packet->data[9];
				*keyid <<= 8;
				*keyid += packet->data[10];
				*keyid <<= 8;
				*keyid += packet->data[11];
				*keyid <<= 8;
				*keyid += packet->data[12];
				*keyid <<= 8;
				*keyid += packet->data[13];
				*keyid <<= 8;
				*keyid += packet->data[14];
			}
			if (creation != NULL) {
				*creation = packet->data[3];
				*creation <<= 8;
				*creation = packet->data[4];
				*creation <<= 8;
				*creation = packet->data[5];
				*creation <<= 8;
				*creation = packet->data[6];
			}
			break;
		case 4:
		case 5:
			if (keyid != NULL) {
				*keyid = 0;
			}
			offset = 4;
			length = (packet->data[offset] << 8) +
				packet->data[offset + 1];
			offset += 2;
			res = parse_subpackets(&packet->data[offset],
					length,
					keyid, creation);
			offset += length;
			if (res != ONAK_E_OK) {
				return res;
			}
			/*
			 * Only look at the unhashed subpackets if we want the
			 * keyid and it wasn't in the signed subpacket
			 * section.
			 */
			if (keyid != NULL && *keyid == 0) {
				length = (packet->data[offset] << 8) +
					packet->data[offset + 1];
				offset += 2;
				res = parse_subpackets(&packet->data[offset],
						length,
						keyid, NULL);
				if (res != ONAK_E_OK) {
					return res;
				}
			}
			break;
		default:
			break;
		}
	}

	return ONAK_E_OK;
}

/**
 *	sig_keyid - Return the keyid for a given OpenPGP signature packet.
 *	@packet: The signature packet.
 *
 *	Returns the keyid for the supplied signature packet.
 */
uint64_t sig_keyid(struct openpgp_packet *packet)
{
	uint64_t keyid = 0;

	sig_info(packet, &keyid, NULL);

	return keyid;
}


/*
 * TODO: Abstract out; all our linked lists should be generic and then we can
 * llsize them.
 */
int spsize(struct openpgp_signedpacket_list *list)
{
	int size = 0;
	struct openpgp_signedpacket_list *cur;

	for (cur = list; cur != NULL; cur = cur->next, size++) ;

	return size;
}

/**
 *	keyuids - Takes a key and returns an array of its UIDs
 *	@key: The key to get the uids of.
 *	@primary: A pointer to store the primary UID in.
 *
 *	keyuids takes a public key structure and builds an array of the UIDs 
 *	on the key. It also attempts to work out the primary UID and returns a
 *	separate pointer to that particular element of the array.
 */
char **keyuids(struct openpgp_publickey *key, char **primary)
{
	struct openpgp_signedpacket_list *curuid = NULL;
	char buf[1024];
	char **uids = NULL;
	int count = 0;
        
        if (primary != NULL) {
        	*primary = NULL;
	}

	if (key != NULL && key->uids != NULL) {
		uids = malloc((spsize(key->uids) + 1) * sizeof (char *));
	
		curuid = key->uids;
		while (curuid != NULL) {
			buf[0] = 0;
			if (curuid->packet->tag == OPENPGP_PACKET_UID) {
				snprintf(buf, 1023, "%.*s",
						(int) curuid->packet->length,
						curuid->packet->data);
				uids[count++] = strdup(buf);
			}
			curuid = curuid -> next;
		}
		uids[count] = NULL;

		/*
		 * TODO: Parse subpackets for real primary ID (v4 keys)
		 */
		if (primary != NULL) {
			*primary = uids[0];
		}
	}

	return uids;
}

/**
 *	keysubkeys - Takes a key and returns an array of its subkey keyids.
 *	@key: The key to get the subkeys of.
 *
 *	keysubkeys takes a public key structure and returns an array of the
 *	subkey keyids for that key.
 */
struct openpgp_fingerprint *keysubkeys(struct openpgp_publickey *key)
{
	struct openpgp_signedpacket_list *cursubkey = NULL;
	struct openpgp_fingerprint       *subkeys = NULL;
	int                               count = 0;

	if (key != NULL && key->subkeys != NULL) {
		subkeys = malloc((spsize(key->subkeys) + 1) *
				sizeof (struct openpgp_fingerprint));
		cursubkey = key->subkeys;
		while (cursubkey != NULL) {
			get_fingerprint(cursubkey->packet, &subkeys[count++]);
			cursubkey = cursubkey -> next;
		}
		subkeys[count].length = 0;
	}

	return subkeys;
}

enum onak_oid onak_parse_oid(uint8_t *buf, size_t len)
{
	enum onak_oid oid;

	/* Elliptic curve key size is based on OID */
	if (len == 0 || (buf[0] >= len)) {
		oid = ONAK_OID_INVALID;
	/* Curve25519 / 1.3.6.1.4.1.3029.1.5.1 */
	} else if ((buf[0] == 10) &&
			(buf[1] == 0x2B) && (buf[2] == 0x06) &&
			(buf[3] == 0x01) && (buf[4] == 0x04) &&
			(buf[5] == 0x01) && (buf[6] == 0x97) &&
			(buf[7] == 0x55) && (buf[8] == 0x01) &&
			(buf[9] == 0x05) && (buf[10] == 0x01)) {
		oid = ONAK_OID_CURVE25519;
	/* Ed25519 / 1.3.6.1.4.1.11591.15.1 */
	} else if ((buf[0] == 9) &&
			(buf[1] == 0x2B) && (buf[2] == 0x06) &&
			(buf[3] == 0x01) && (buf[4] == 0x04) &&
			(buf[5] == 0x01) && (buf[6] == 0xDA) &&
			(buf[7] == 0x47) && (buf[8] == 0x0F) &&
			(buf[9] == 0x01)) {
		oid = ONAK_OID_ED25519;
	/* nistp256 / 1.2.840.10045.3.1.7 */
	} else if ((buf[0] == 8) &&
			(buf[1] == 0x2A) && (buf[2] == 0x86) &&
			(buf[3] == 0x48) && (buf[4] == 0xCE) &&
			(buf[5] == 0x3D) && (buf[6] == 0x03) &&
			(buf[7] == 0x01) && (buf[8] == 0x07)) {
		oid = ONAK_OID_NISTP256;
	/* nistp384 / 1.3.132.0.34 */
	} else if ((buf[0] == 5) &&
			(buf[1] == 0x2B) && (buf[2] == 0x81) &&
			(buf[3] == 0x04) && (buf[4] == 0x00) &&
			(buf[5] == 0x22)) {
		oid = ONAK_OID_NISTP384;
	/* nistp521 / 1.3.132.0.35 */
	} else if ((buf[0] == 5) &&
			(buf[1] == 0x2B) && (buf[2] == 0x81) &&
			(buf[3] == 0x04) && (buf[4] == 0x00) &&
			(buf[5] == 0x23)) {
		oid = ONAK_OID_NISTP521;
	/* brainpoolP256r1 / 1.3.36.3.3.2.8.1.1.7 */
	} else if ((buf[0] == 9) &&
			(buf[1] == 0x2B) && (buf[2] == 0x24) &&
			(buf[3] == 0x03) && (buf[4] == 0x03) &&
			(buf[5] == 0x02) && (buf[6] == 0x08) &&
			(buf[7] == 0x01) && (buf[8] == 0x01) &&
			(buf[9] == 0x07)) {
		oid = ONAK_OID_BRAINPOOLP256R1;
	/* brainpoolP384r1 / 1.3.36.3.3.2.8.1.1.11 */
	} else if ((buf[0] == 9) &&
			(buf[1] == 0x2B) && (buf[2] == 0x24) &&
			(buf[3] == 0x03) && (buf[4] == 0x03) &&
			(buf[5] == 0x02) && (buf[6] == 0x08) &&
			(buf[7] == 0x01) && (buf[8] == 0x01) &&
			(buf[9] == 0x0B)) {
		oid = ONAK_OID_BRAINPOOLP384R1;
	/* brainpoolP512r1 / 1.3.36.3.3.2.8.1.1.13 */
	} else if ((buf[0] == 9) &&
			(buf[1] == 0x2B) && (buf[2] == 0x24) &&
			(buf[3] == 0x03) && (buf[4] == 0x03) &&
			(buf[5] == 0x02) && (buf[6] == 0x08) &&
			(buf[7] == 0x01) && (buf[8] == 0x01) &&
			(buf[9] == 0x0D)) {
		oid = ONAK_OID_BRAINPOOLP512R1;
	/* secp256k1 / 1.3.132.0.10 */
	} else if ((buf[0] == 5) &&
			(buf[1] == 0x2B) && (buf[2] == 0x81) &&
			(buf[3] == 0x04) && (buf[4] == 0x00) &&
			(buf[5] == 0x0A)) {
		oid = ONAK_OID_SECP256K1;
	} else {
		oid = ONAK_OID_UNKNOWN;
	}

	return oid;
}
