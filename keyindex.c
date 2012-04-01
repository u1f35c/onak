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
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "decodekey.h"
#include "getcgi.h"
#include "hash.h"
#include "keydb.h"
#include "keyid.h"
#include "keyindex.h"
#include "keystructs.h"
#include "log.h"
#include "onak-conf.h"
#include "openpgp.h"

int list_sigs(struct openpgp_packet_list *sigs, bool html)
{
	char *uid = NULL;
	uint64_t sigid = 0;
	char *sig = NULL;

	while (sigs != NULL) {
		sigid = sig_keyid(sigs->packet);
		uid = config.dbbackend->keyid2uid(sigid);
		if (sigs->packet->data[0] == 4 &&
				sigs->packet->data[1] == 0x30) {
			/* It's a Type 4 sig revocation */
			sig = "rev";
		} else {
			sig = "sig";
		}
		if (html && uid != NULL) {
			printf("%s         <a href=\"lookup?op=get&"
				"search=%016" PRIX64 "\">%08" PRIX64
				"</a>             "
				"<a href=\"lookup?op=vindex&search=0x%016"
				PRIX64 "\">%s</a>\n",
				sig,
				sigid,
				sigid & 0xFFFFFFFF,
				sigid,
				txt2html(uid));
		} else if (html && uid == NULL) {
			printf("%s         %08" PRIX64 "             "
				"[User id not found]\n",
				sig,
				sigid & 0xFFFFFFFF);
		} else {
			printf("%s         %08" PRIX64
				"             %s\n",
				sig,
				sigid & 0xFFFFFFFF,
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

int list_uids(uint64_t keyid, struct openpgp_signedpacket_list *uids,
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
			list_sigs(uids->sigs, html);
		}
		uids = uids->next;
	}

	return 0;
}

int list_subkeys(struct openpgp_signedpacket_list *subkeys, bool verbose,
		bool html)
{
	struct tm	*created = NULL;
	time_t		created_time = 0;
	int	 	type = 0;
	int	 	length = 0;

	while (subkeys != NULL) {
		if (subkeys->packet->tag == OPENPGP_PACKET_PUBLICSUBKEY) {

			created_time = (subkeys->packet->data[1] << 24) +
					(subkeys->packet->data[2] << 16) +
					(subkeys->packet->data[3] << 8) +
					subkeys->packet->data[4];
			created = gmtime(&created_time);

			switch (subkeys->packet->data[0]) {
			case 2:
			case 3:
				type = subkeys->packet->data[7];
				length = (subkeys->packet->data[8] << 8) +
					subkeys->packet->data[9];
				break;
			case 4:
				type = subkeys->packet->data[5];
				length = (subkeys->packet->data[6] << 8) +
					subkeys->packet->data[7];
				break;
			default:
				logthing(LOGTHING_ERROR,
					"Unknown key type: %d",
					subkeys->packet->data[0]);
			}
		
			printf("sub  %5d%c/%08X %04d/%02d/%02d\n",
				length,
				(type == OPENPGP_PKALGO_RSA) ? 'R' :
				((type == OPENPGP_PKALGO_ELGAMAL) ? 'g' :
				((type == OPENPGP_PKALGO_DSA) ? 'D' : '?')),
				(uint32_t) (get_packetid(subkeys->packet) &
					    0xFFFFFFFF),
				created->tm_year + 1900,
				created->tm_mon + 1,
				created->tm_mday);

		}
		if (verbose) {
			list_sigs(subkeys->sigs, html);
		}
		subkeys = subkeys->next;
	}

	return 0;
}

void display_fingerprint(struct openpgp_publickey *key)
{
	int		i = 0;
	size_t		length = 0;
	unsigned char	fp[20];

	get_fingerprint(key->publickey, fp, &length);
	printf("      Key fingerprint =");
	for (i = 0; i < length; i++) {
		if ((length == 16) ||
			(i % 2 == 0)) {
			printf(" ");
		}
		if (length == 20 && (i * 2) == length) {
			/* Extra space in the middle of a SHA1 fingerprint */
			printf(" ");
		}
		printf("%02X", fp[i]);
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
int key_index(struct openpgp_publickey *keys, bool verbose, bool fingerprint,
			bool skshash, bool html)
{
	struct openpgp_signedpacket_list	*curuid = NULL;
	struct tm				*created = NULL;
	time_t					 created_time = 0;
	int					 type = 0;
	char					 typech;
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
		created = gmtime(&created_time);

		switch (keys->publickey->data[0]) {
		case 2:
		case 3:
			type = keys->publickey->data[7];
			length = (keys->publickey->data[8] << 8) +
					keys->publickey->data[9];
			break;
		case 4:
			type = keys->publickey->data[5];
			length = (keys->publickey->data[6] << 8) +
					keys->publickey->data[7];
			break;
		default:
			logthing(LOGTHING_ERROR, "Unknown key type: %d",
				keys->publickey->data[0]);
		}
		
		keyid = get_keyid(keys);

		switch (type) {
		case OPENPGP_PKALGO_RSA:
			typech = 'R';
			break;
		case OPENPGP_PKALGO_ELGAMAL:
			typech = 'g';
			break;
		case OPENPGP_PKALGO_DSA:
			typech = 'D';
			break;
		case OPENPGP_PKALGO_ELGAMAL_SIGN:
			typech = 'G';
			break;
		default:
			typech = '?';
			break;
		}

		if (html) {
			printf("pub  %5d%c/<a href=\"lookup?op=get&"
				"search=%016" PRIX64 "\">%08" PRIX64
				"</a> %04d/%02d/%02d ",
				length,
				typech,
				keyid,
				keyid & 0xFFFFFFFF,
				created->tm_year + 1900,
				created->tm_mon + 1,
				created->tm_mday);
		} else {
			printf("pub  %5d%c/%08" PRIX64 " %04d/%02d/%02d ",
				length,
				typech,
				keyid & 0xFFFFFFFF,
				created->tm_year + 1900,
				created->tm_mon + 1,
				created->tm_mday);
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
				list_sigs(curuid->sigs, html);
			}
			curuid = curuid->next;
		} else {
			printf("%s\n", 
				(keys->revoked) ? "*** REVOKED ***": "");
			if (fingerprint) {
				display_fingerprint(keys);
			}
		}

		list_uids(keyid, curuid, verbose, html);
		if (verbose) {
			list_subkeys(keys->subkeys, verbose, html);
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
	size_t					 fplength = 0;
	unsigned char				 fp[20];
	int					 c;

	while (keys != NULL) {
		created_time = (keys->publickey->data[1] << 24) +
					(keys->publickey->data[2] << 16) +
					(keys->publickey->data[3] << 8) +
					keys->publickey->data[4];

		printf("pub:");

		switch (keys->publickey->data[0]) {
		case 2:
		case 3:
			printf("%016" PRIX64, get_keyid(keys));
			type = keys->publickey->data[7];
			length = (keys->publickey->data[8] << 8) +
					keys->publickey->data[9];
			break;
		case 4:
			(void) get_fingerprint(keys->publickey, fp, &fplength);

			for (i = 0; i < fplength; i++) {
				printf("%02X", fp[i]);
			}

			type = keys->publickey->data[5];
			length = (keys->publickey->data[6] << 8) +
					keys->publickey->data[7];
			break;
		default:
			logthing(LOGTHING_ERROR, "Unknown key type: %d",
				keys->publickey->data[0]);
		}

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
