/*
 * keyindex.c - Routines to list an OpenPGP key.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "getcgi.h"
#include "hash.h"
#include "keydb.h"
#include "keyid.h"
#include "keyindex.h"
#include "keystructs.h"
#include "ll.h"
#include "stats.h"

int parse_subpackets(unsigned char *data, bool html)
{
	int offset = 0;
	int length = 0;
	int packetlen = 0;
	char *uid;

	assert(data != NULL);

	length = (data[0] << 8) + data[1] + 2;

	offset = 2;
	while (offset < length) {
		packetlen = data[offset++];
		if (packetlen > 191 && packetlen < 255) {
			packetlen = ((packetlen - 192) << 8) +
					data[offset++] + 192;
		} else if (packetlen == 255) {
			packetlen = data[offset++];
			packetlen <<= 8;
			packetlen = data[offset++];
			packetlen <<= 8;
			packetlen = data[offset++];
			packetlen <<= 8;
			packetlen = data[offset++];
		}
		switch (data[offset]) {
		case 2:
			/*
			 * Signature creation time. Might want to output this?
			 */
			break;
		case 16:
			uid = keyid2uid((data[offset+packetlen - 4] << 24) +
	                                (data[offset+packetlen - 3] << 16) +
	                                (data[offset+packetlen - 2] << 8) +
	                                data[offset+packetlen - 1]);
			if (html && uid != NULL) {
				printf("sig        <a href=\"lookup?op=get&"
					"search=%02X%02X%02X%02X\">"
					"%02X%02X%02X%02X</a>             "
					"<a href=\"lookup?op=vindex&"
					"search=0x%02X%02X%02X%02X\">"
					"%s</a>\n",
					data[offset+packetlen - 4],
					data[offset+packetlen - 3],
					data[offset+packetlen - 2],
					data[offset+packetlen - 1],
					data[offset+packetlen - 4],
					data[offset+packetlen - 3],
					data[offset+packetlen - 2],
					data[offset+packetlen - 1],

					data[offset+packetlen - 4],
					data[offset+packetlen - 3],
					data[offset+packetlen - 2],
					data[offset+packetlen - 1],
					txt2html(uid));
			} else if (html && uid == NULL) {
				printf("sig        "
					"%02X%02X%02X%02X             "
					"[User id not found]\n",
					data[offset+packetlen - 4],
					data[offset+packetlen - 3],
					data[offset+packetlen - 2],
					data[offset+packetlen - 1]);
			} else {
				printf("sig        %02X%02X%02X%02X"
						"             %s\n",
					data[offset+packetlen - 4],
					data[offset+packetlen - 3],
					data[offset+packetlen - 2],
					data[offset+packetlen - 1],
					(uid != NULL) ? uid :
					"[User id not found]");
			}
			break;
		default:
			/*
			 * We don't care about unrecognized packets unless bit
			 * 7 is set in which case we prefer an error than
			 * ignoring it.
			 */
			assert(!(data[offset] & 0x80));
		}
		offset += packetlen;
	}

	return length;
}

int list_sigs(struct openpgp_packet_list *sigs, bool html)
{
	int length = 0;
	char *uid;

	while (sigs != NULL) {
		switch (sigs->packet->data[0]) {
		case 2:
		case 3:
			uid = keyid2uid((sigs->packet->data[11] << 24) +
	                                (sigs->packet->data[12] << 16) +
	                                (sigs->packet->data[13] << 8) +
	                                sigs->packet->data[14]);
			if (html && uid != NULL) {
				printf("sig        <a href=\"lookup?op=get&"
					"search=%02X%02X%02X%02X\">"
					"%02X%02X%02X%02X</a>             "
					"<a href=\"lookup?op=vindex&"
					"search=0x%02X%02X%02X%02X\">"
					"%s</a>\n",
					sigs->packet->data[11],
					sigs->packet->data[12],
					sigs->packet->data[13],
					sigs->packet->data[14],
					sigs->packet->data[11],
					sigs->packet->data[12],
					sigs->packet->data[13],
					sigs->packet->data[14],

					sigs->packet->data[11],
					sigs->packet->data[12],
					sigs->packet->data[13],
					sigs->packet->data[14],
					txt2html(uid));
			} else if (html && uid == NULL) {
				printf("sig        %02X%02X%02X%02X"
					"             "
					"[User id not found]\n",
					sigs->packet->data[11],
					sigs->packet->data[12],
					sigs->packet->data[13],
					sigs->packet->data[14]);
			} else {
				printf("sig        %02X%02X%02X%02X"
						"             %s\n",
					sigs->packet->data[11],
					sigs->packet->data[12],
					sigs->packet->data[13],
					sigs->packet->data[14],
					(uid != NULL) ? uid :
					"[User id not found]");
			}
			break;
		case 4:
			length = parse_subpackets(&sigs->packet->data[4], html);
			parse_subpackets(&sigs->packet->data[length + 4], html);
			break;
		default:
			printf("sig        [Unknown packet version %d]",
					sigs->packet->data[0]);
		}
		sigs = sigs->next;
	}

	return 0;
}

int list_uids(struct openpgp_signedpacket_list *uids, bool verbose, bool html)
{
	char buf[1024];

	while (uids != NULL) {
		if (uids->packet->tag == 13) {
			snprintf(buf, 1023, "%.*s",
				(int) uids->packet->length,
				uids->packet->data);
			printf("uid                            %s\n",
				(html) ? txt2html(buf) : buf);
		} else if (uids->packet->tag == 17) {
			printf("uid                            "
				"[photo id]\n");
		}
		if (verbose) {
			list_sigs(uids->sigs, html);
		}
		uids = uids->next;
	}

	return 0;
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
			bool html)
{
	struct openpgp_signedpacket_list	*curuid = NULL;
	struct tm				*created = NULL;
	time_t					 created_time = 0;
	int					 type = 0;
	int					 length = 0;
	char					 buf[1024];

	if (html) {
		puts("<pre>");
	}
	puts("Type  bits/keyID    Date       User ID");
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
			fprintf(stderr, "Unknown key type: %d\n",
				keys->publickey->data[0]);
		}
		
		printf("pub  %4d%c/%08X %04d/%02d/%02d ",
			length,
			(type == 1) ? 'R' : ((type == 17) ? 'D' : '?'),
			(uint32_t) (get_keyid(keys) & 0xFFFFFFFF),
			created->tm_year + 1900,
			created->tm_mon + 1,
			created->tm_mday);

		curuid = keys->uids;
		if (curuid != NULL && curuid->packet->tag == 13) {
			snprintf(buf, 1023, "%.*s",
				(int) curuid->packet->length,
				curuid->packet->data);
			printf("%s\n", (html) ? txt2html(buf) : buf);
			if (verbose) {

				list_sigs(curuid->sigs, html);
			}
			curuid = curuid->next;
		} else {
			putchar('\n');
		}

		list_uids(curuid, verbose, html);

		//TODO: List subkeys.

		keys = keys->next;
	}

	if (html) {
		puts("</pre>");
	}

	return 0;
}


int get_subpackets_keyid(unsigned char *data, uint64_t *keyid)
{
	int offset = 0;
	int length = 0;
	int packetlen = 0;

	assert(data != NULL);

	length = (data[0] << 8) + data[1] + 2;

	offset = 2;
	while (offset < length) {
		packetlen = data[offset++];
		if (packetlen > 191 && packetlen < 255) {
			packetlen = ((packetlen - 192) << 8) +
					data[offset++] + 192;
		} else if (packetlen == 255) {
			packetlen = data[offset++];
			packetlen <<= 8;
			packetlen = data[offset++];
			packetlen <<= 8;
			packetlen = data[offset++];
			packetlen <<= 8;
			packetlen = data[offset++];
		}
		switch (data[offset]) {
		case 2:
			/*
			 * Signature creation time. Might want to output this?
			 */
			break;
		case 16:
			*keyid = (data[offset+packetlen - 4] << 24) +
				(data[offset+packetlen - 3] << 16) +
				(data[offset+packetlen - 2] << 8) +
				data[offset+packetlen - 1];
			*keyid &= 0xFFFFFFFF;
			break;
		default:
			/*
			 * We don't care about unrecognized packets unless bit
			 * 7 is set in which case we prefer an error than
			 * ignoring it.
			 */
			assert(!(data[offset] & 0x80));
		}
		offset += packetlen;
	}

	return length;
}


/**
 *	keysigs - Return the sigs on a given OpenPGP signature list.
 *	@curll: The current linked list. Can be NULL to create a new list.
 *	@sigs: The signature list we want the sigs on.
 *
 *	Returns a linked list of stats_key elements containing the sigs on the
 *	supplied OpenPGP packet list.
 */
struct ll *keysigs(struct ll *curll,
		struct openpgp_packet_list *sigs)
{
	int length = 0;
	uint64_t keyid = 0;
	
	while (sigs != NULL) {
		keyid = 0;
		switch (sigs->packet->data[0]) {
		case 2:
		case 3:
			keyid = sigs->packet->data[11] << 24;
			keyid += (sigs->packet->data[12] << 16);
			keyid += (sigs->packet->data[13] << 8);
			keyid += sigs->packet->data[14];
			keyid &= 0xFFFFFFFF;
			break;
		case 4:
			length = get_subpackets_keyid(&sigs->packet->data[4],
					&keyid);
			get_subpackets_keyid(&sigs->packet->data[length + 4],
					&keyid);
			/*
			 * Don't bother to look at the unsigned packets.
			 */
			break;
		default:
			break;
		}
		sigs = sigs->next;
		curll = lladd(curll, createandaddtohash(keyid));
	}

	return curll;
}
