/*
 * keyindex.c - Routines to list an OpenPGP key.
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

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "decodekey.h"
#include "keydb.h"
#include "keyid.h"
#include "keyindex.h"
#include "keystructs.h"
#include "log.h"
#include "onak.h"
#include "openpgp.h"

/*
 * Convert a Public Key algorithm to its single character representation.
 */
char pkalgo2char(uint8_t algo)
{
	char typech;

	switch (algo) {
	case OPENPGP_PKALGO_DSA:
		typech = 'D';
		break;
	case OPENPGP_PKALGO_ECDSA:
	case OPENPGP_PKALGO_EDDSA:
		typech = 'E';
		break;
	case OPENPGP_PKALGO_EC:
		typech = 'e';
		break;
	case OPENPGP_PKALGO_ELGAMAL_SIGN:
		typech = 'G';
		break;
	case OPENPGP_PKALGO_ELGAMAL_ENC:
		typech = 'g';
		break;
	case OPENPGP_PKALGO_RSA:
		typech = 'R';
		break;
	case OPENPGP_PKALGO_RSA_ENC:
		typech = 'r';
		break;
	case OPENPGP_PKALGO_RSA_SIGN:
		typech = 's';
		break;
	default:
		typech = '?';
		break;
	}

	return typech;
}

/**
 *	txt2html - Takes a string and converts it to HTML.
 *	@string: The string to HTMLize.
 *
 *	Takes a string and escapes any HTML entities.
 */
const char *txt2html(const char *string)
{
	static char buf[1024];
	char *ptr = NULL;
	char *nextptr = NULL;

	if (strlen(string) > 1000) {
		return string;
	}

	memset(buf, 0, 1024);

	ptr = strchr(string, '<');
	if (ptr != NULL) {
		nextptr = ptr + 1;
		*ptr = 0;
		strncpy(buf, string, 1023);
		strncat(buf, "&lt;", 1023 - strlen(buf));
		string = nextptr;
	}

	ptr = strchr(string, '>');
	if (ptr != NULL) {
		nextptr = ptr + 1;
		*ptr = 0;
		strncat(buf, string, 1023 - strlen(buf));
		strncat(buf, "&gt;", 1023 - strlen(buf));
		string = nextptr;
	}

	/*
	 * TODO: We need to while() this really as each entity may appear more
	 * than once. We need to start with & and ; as we replace with those
	 * throughout. Fuck it for the moment though; it's Easter and < & > are
	 * the most common and tend to only appear once.
	 */

	strncat(buf, string, 1023 - strlen(buf));

	return buf;
}

/*
 * Given a public key/subkey packet return the key length.
 */
unsigned int keylength(struct openpgp_packet *keydata)
{
	unsigned int length;
	uint8_t keyofs;
	enum onak_oid oid;

	switch (keydata->data[0]) {
	case 2:
	case 3:
		length = (keydata->data[8] << 8) +
				keydata->data[9];
		break;
	case 4:
	case 5:
		/* v5 has an additional 4 bytes of key length data */
		keyofs = (keydata->data[0] == 4) ? 6 : 10;
		switch (keydata->data[5]) {
		case OPENPGP_PKALGO_EC:
		case OPENPGP_PKALGO_ECDSA:
		case OPENPGP_PKALGO_EDDSA:
			/* Elliptic curve key size is based on OID */
			oid = onak_parse_oid(&keydata->data[keyofs],
					keydata->length - keyofs);
			if (oid == ONAK_OID_CURVE25519) {
				length = 255;
			} else if (oid == ONAK_OID_ED25519) {
				length = 255;
			} else if (oid == ONAK_OID_NISTP256) {
				length = 256;
			} else if (oid == ONAK_OID_NISTP384) {
				length = 384;
			} else if (oid == ONAK_OID_NISTP521) {
				length = 521;
			} else if (oid == ONAK_OID_BRAINPOOLP256R1) {
				length = 256;
			} else if (oid == ONAK_OID_BRAINPOOLP384R1) {
				length = 384;
			} else if (oid == ONAK_OID_BRAINPOOLP512R1) {
				length = 512;
			} else if (oid == ONAK_OID_SECP256K1) {
				length = 256;
			} else {
				logthing(LOGTHING_ERROR,
					"Unknown elliptic curve size");
				length = 0;
			}
			break;
		default:
			length = (keydata->data[keyofs] << 8) +
				keydata->data[keyofs + 1];
		}
		break;
	default:
		logthing(LOGTHING_ERROR, "Unknown key version: %d",
			keydata->data[0]);
		length = 0;
	}

	return length;
}

int list_sigs(struct onak_dbctx *dbctx,
		struct openpgp_packet_list *sigs, bool html)
{
	char *uid = NULL;
	uint64_t sigid = 0;
	char *sig = NULL;

	while (sigs != NULL) {
		sigid = sig_keyid(sigs->packet);
		if (dbctx) {
			uid = dbctx->keyid2uid(dbctx, sigid);
		}
		if (sigs->packet->data[0] == 4 &&
				sigs->packet->data[1] == 0x30) {
			/* It's a Type 4 sig revocation */
			sig = "rev";
		} else {
			sig = "sig";
		}
		if (html && uid != NULL) {
			printf("%s         <a href=\"lookup?op=get&"
				"search=0x%016" PRIX64 "\">0x%016" PRIX64
				"</a>             "
				"<a href=\"lookup?op=vindex&search=0x%016"
				PRIX64 "\">%s</a>\n",
				sig,
				sigid,
				sigid,
				sigid,
				txt2html(uid));
		} else if (html && uid == NULL) {
			printf("%s         0x%016" PRIX64 "             "
				"[User id not found]\n",
				sig,
				sigid);
		} else {
			printf("%s         0x%016" PRIX64
				"             %s\n",
				sig,
				sigid,
				(uid != NULL) ? uid :
				"[User id not found]");
		}
		if (uid != NULL) {
			free(uid);
			uid = NULL;
		}
		sigs = sigs->next;
	}

	return 0;
}

int list_uids(struct onak_dbctx *dbctx,
		uint64_t keyid, struct openpgp_signedpacket_list *uids,
		bool verbose, bool html)
{
	char buf[1024];
	int  imgindx = 0;

	while (uids != NULL) {
		if (uids->packet->tag == OPENPGP_PACKET_UID) {
			snprintf(buf, 1023, "%.*s",
				(int) uids->packet->length,
				uids->packet->data);
			printf("                                %s\n",
				(html) ? txt2html(buf) : buf);
		} else if (uids->packet->tag == OPENPGP_PACKET_UAT) {
			printf("                                ");
			if (html) {
				printf("<img src=\"lookup?op=photo&search="
					"0x%016" PRIX64 "&idx=%d\" alt=\""
					"[photo id]\">\n",
					keyid,
					imgindx);
				imgindx++;
			} else {
				printf("[photo id]\n");
			}
		}
		if (verbose) {
			list_sigs(dbctx, uids->sigs, html);
		}
		uids = uids->next;
	}

	return 0;
}

int list_subkeys(struct onak_dbctx *dbctx,
		struct openpgp_signedpacket_list *subkeys, bool verbose,
		bool html)
{
	struct tm	created;
	time_t		created_time = 0;
	int	 	type = 0;
	int	 	length = 0;
	uint64_t	keyid = 0;

	while (subkeys != NULL) {
		if (subkeys->packet->tag == OPENPGP_PACKET_PUBLICSUBKEY) {

			created_time = (subkeys->packet->data[1] << 24) +
					(subkeys->packet->data[2] << 16) +
					(subkeys->packet->data[3] << 8) +
					subkeys->packet->data[4];
			gmtime_r(&created_time, &created);

			switch (subkeys->packet->data[0]) {
			case 2:
			case 3:
				type = subkeys->packet->data[7];
				break;
			case 4:
			case 5:
				type = subkeys->packet->data[5];
				break;
			default:
				logthing(LOGTHING_ERROR,
					"Unknown key version: %d",
					subkeys->packet->data[0]);
			}
			length = keylength(subkeys->packet);

			if (get_packetid(subkeys->packet,
					&keyid) != ONAK_E_OK) {
				logthing(LOGTHING_ERROR, "Couldn't get keyid.");
			}
			printf("sub  %5d%c/0x%016" PRIX64 " %04d/%02d/%02d\n",
				length,
				pkalgo2char(type),
				keyid,
				created.tm_year + 1900,
				created.tm_mon + 1,
				created.tm_mday);

		}
		if (verbose) {
			list_sigs(dbctx, subkeys->sigs, html);
		}
		subkeys = subkeys->next;
	}

	return 0;
}

void display_fingerprint(struct openpgp_publickey *key)
{
	int		i = 0;
	struct openpgp_fingerprint fingerprint;

	get_fingerprint(key->publickey, &fingerprint);
	printf("      Key fingerprint =");
	for (i = 0; i < fingerprint.length; i++) {
		if ((fingerprint.length == 16) ||
			(i % 2 == 0)) {
			printf(" ");
		}
		if (fingerprint.length == 20 &&
				(i * 2) == fingerprint.length) {
			/* Extra space in the middle of a SHA1 fingerprint */
			printf(" ");
		}
		printf("%02X", fingerprint.fp[i]);
	}
	printf("\n");

	return;
}

void display_skshash(struct openpgp_publickey *key, bool html)
{
	int		i = 0;
	struct skshash	hash;

	get_skshash(key, &hash);
	printf("      Key hash = ");
	if (html) {
		printf("<a href=\"lookup?op=hget&search=");
		for (i = 0; i < sizeof(hash.hash); i++) {
			printf("%02X", hash.hash[i]);
		}
		printf("\">");
	}
	for (i = 0; i < sizeof(hash.hash); i++) {
		printf("%02X", hash.hash[i]);
	}
	if (html) {
		printf("</a>");
	}
	printf("\n");

	return;
}

/**
 *	key_index - List a set of OpenPGP keys.
 *	@keys: The keys to display.
 *      @verbose: Should we list sigs as well?
 *	@fingerprint: List the fingerprint?
 *	@html: Should the output be tailored for HTML?
 *
 *	This function takes a list of OpenPGP public keys and displays an index
 *	of them. Useful for debugging or the keyserver Index function.
 */
int key_index(struct onak_dbctx *dbctx,
		struct openpgp_publickey *keys, bool verbose, bool fingerprint,
			bool skshash, bool html)
{
	struct openpgp_signedpacket_list	*curuid = NULL;
	struct tm				 created;
	time_t					 created_time = 0;
	int					 type = 0;
	int					 length = 0;
	char					 buf[1024];
	uint64_t				 keyid;


	if (html) {
		puts("<pre>");
	}
	puts("Type   bits/keyID    Date       User ID");
	while (keys != NULL) {
		created_time = (keys->publickey->data[1] << 24) +
					(keys->publickey->data[2] << 16) +
					(keys->publickey->data[3] << 8) +
					keys->publickey->data[4];
		gmtime_r(&created_time, &created);

		switch (keys->publickey->data[0]) {
		case 2:
		case 3:
			type = keys->publickey->data[7];
			break;
		case 4:
		case 5:
			type = keys->publickey->data[5];
			break;
		default:
			logthing(LOGTHING_ERROR, "Unknown key version: %d",
				keys->publickey->data[0]);
		}
		length = keylength(keys->publickey);

		if (get_keyid(keys, &keyid) != ONAK_E_OK) {
			logthing(LOGTHING_ERROR, "Couldn't get keyid.");
		}

		if (html) {
			printf("pub  %5d%c/<a href=\"lookup?op=get&"
				"search=0x%016" PRIX64 "\">0x%016" PRIX64
				"</a> %04d/%02d/%02d ",
				length,
				pkalgo2char(type),
				keyid,
				keyid,
				created.tm_year + 1900,
				created.tm_mon + 1,
				created.tm_mday);
		} else {
			printf("pub  %5d%c/0x%016" PRIX64 " %04d/%02d/%02d ",
				length,
				pkalgo2char(type),
				keyid,
				created.tm_year + 1900,
				created.tm_mon + 1,
				created.tm_mday);
		}

		curuid = keys->uids;
		if (curuid != NULL &&
				curuid->packet->tag == OPENPGP_PACKET_UID) {
			snprintf(buf, 1023, "%.*s",
				(int) curuid->packet->length,
				curuid->packet->data);
			if (html) {
				printf("<a href=\"lookup?op=vindex&"
					"search=0x%016" PRIX64 "\">",
					keyid);
			}
			printf("%s%s%s\n", 
				(html) ? txt2html(buf) : buf,
				(html) ? "</a>" : "",
				(keys->revoked) ? " *** REVOKED ***" : "");
			if (skshash) {
				display_skshash(keys, html);
			}
			if (fingerprint) {
				display_fingerprint(keys);
			}
			if (verbose) {
				list_sigs(dbctx, curuid->sigs, html);
			}
			curuid = curuid->next;
		} else {
			printf("%s\n", 
				(keys->revoked) ? "*** REVOKED ***": "");
			if (fingerprint) {
				display_fingerprint(keys);
			}
		}

		list_uids(dbctx, keyid, curuid, verbose, html);
		if (verbose) {
			list_subkeys(dbctx, keys->subkeys, verbose, html);
		}

		keys = keys->next;
	}

	if (html) {
		puts("</pre>");
	}

	return 0;
}

/**
 *	mrkey_index - List a set of OpenPGP keys in the MRHKP format.
 *	@keys: The keys to display.
 *
 *	This function takes a list of OpenPGP public keys and displays a
 *	machine readable list of them.
 */
int mrkey_index(struct openpgp_publickey *keys)
{
	struct openpgp_signedpacket_list	*curuid = NULL;
	time_t					 created_time = 0;
	int					 type = 0;
	int					 length = 0;
	int					 i = 0;
	int					 c;
	uint64_t				 keyid;
	struct openpgp_fingerprint fingerprint;

	while (keys != NULL) {
		created_time = (keys->publickey->data[1] << 24) +
					(keys->publickey->data[2] << 16) +
					(keys->publickey->data[3] << 8) +
					keys->publickey->data[4];

		printf("pub:");

		switch (keys->publickey->data[0]) {
		case 2:
		case 3:
			if (get_keyid(keys, &keyid) != ONAK_E_OK) {
				logthing(LOGTHING_ERROR, "Couldn't get keyid");
			}
			printf("%016" PRIX64, keyid);
			type = keys->publickey->data[7];
			break;
		case 4:
		case 5:
			(void) get_fingerprint(keys->publickey, &fingerprint);

			for (i = 0; i < fingerprint.length; i++) {
				printf("%02X", fingerprint.fp[i]);
			}

			type = keys->publickey->data[5];
			break;
		default:
			logthing(LOGTHING_ERROR, "Unknown key version: %d",
				keys->publickey->data[0]);
		}
		length = keylength(keys->publickey);

		printf(":%d:%d:%ld::%s\n",
			type,
			length,
			created_time,
			(keys->revoked) ? "r" : "");
	
		for (curuid = keys->uids; curuid != NULL;
			 curuid = curuid->next) {
		
			if (curuid->packet->tag == OPENPGP_PACKET_UID) {
				printf("uid:");
				for (i = 0; i < (int) curuid->packet->length;
						i++) {
					c = curuid->packet->data[i];
					if (c == '%') {
						putchar('%');
						putchar(c);
					} else if (c == ':' || c > 127) {
						printf("%%%X", c);
					} else {
						putchar(c);
					}
				}
				printf("\n");
			}
		}
		keys = keys->next;
	}
	return 0;
}
