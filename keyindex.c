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
#include <stdint.h>
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

int list_sigs(struct openpgp_packet_list *sigs, bool html)
{
	int length = 0;
	char *uid = NULL;
	uint64_t sigid = 0;

	while (sigs != NULL) {
		sigid = sig_keyid(sigs->packet);
		uid = keyid2uid(sigid);
		if (html && uid != NULL) {
			printf("sig         <a href=\"lookup?op=get&"
				"search=%08llX\">%08llX</a>             "
				"<a href=\"lookup?op=vindex&search=0x%08llX\">"
				"%s</a>\n",
				sigid & 0xFFFFFFFF,
				sigid & 0xFFFFFFFF,
				sigid & 0xFFFFFFFF,
				txt2html(uid));
		} else if (html && uid == NULL) {
			printf("sig         %08llX             "
				"[User id not found]\n",
				sigid & 0xFFFFFFFF);
		} else {
			printf("sig         %08llX"
				"             %s\n",
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

int list_uids(struct openpgp_signedpacket_list *uids, bool verbose, bool html)
{
	char buf[1024];

	while (uids != NULL) {
		if (uids->packet->tag == 13) {
			snprintf(buf, 1023, "%.*s",
				(int) uids->packet->length,
				uids->packet->data);
			printf("uid                             %s\n",
				(html) ? txt2html(buf) : buf);
		} else if (uids->packet->tag == 17) {
			printf("uid                             "
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
			fprintf(stderr, "Unknown key type: %d\n",
				keys->publickey->data[0]);
		}
		
		printf("pub  %5d%c/%08X %04d/%02d/%02d ",
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

/*
 *	parse_subpackets - Parse the subpackets of a Type 4 signature.
 *	@data: The subpacket data.
 *      @keyid: A pointer to where we should return the keyid.
 *
 *	This function parses the subkey data of a Type 4 signature and fills
 *	in the supplied variables. It also returns the length of the data
 *	processed.
 */
int parse_subpackets(unsigned char *data, uint64_t *keyid)
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
		case 0x83:
			/*
			 * Signature expiration time. Might want to output this?
			 */
			break;
		case 16:
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
			break;
		case 23:
			/*
			 * Key server preferences. Including no-modify.
			 */
			break;
		case 25:
			/*
			 * Primary UID.
			 */
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
	uint64_t keyid = 0;
	
	while (sigs != NULL) {
		keyid = sig_keyid(sigs->packet);
		sigs = sigs->next;
		curll = lladd(curll, createandaddtohash(keyid));
	}

	return curll;
}

/**
 *	sig_keyid - Return the keyid for a given OpenPGP signature packet.
 *	@packet: The signature packet.
 *
 *	Returns the keyid for the supplied signature packet.
 */
uint64_t sig_keyid(struct openpgp_packet *packet)
{
	int length = 0;
	uint64_t keyid = 0;
	
	if (packet != NULL) {
		keyid = 0;
		switch (packet->data[0]) {
		case 2:
		case 3:
			keyid = packet->data[7];
			keyid <<= 8;
			keyid += packet->data[8];
			keyid <<= 8;
			keyid += packet->data[9];
			keyid <<= 8;
			keyid += packet->data[10];
			keyid <<= 8;
			keyid += packet->data[11];
			keyid <<= 8;
			keyid += packet->data[12];
			keyid <<= 8;
			keyid += packet->data[13];
			keyid <<= 8;
			keyid += packet->data[14];
			break;
		case 4:
			length = parse_subpackets(&packet->data[4],
					&keyid);
			parse_subpackets(&packet->data[length + 4],
					&keyid);
			/*
			 * Don't bother to look at the unsigned packets.
			 */
			break;
		default:
			break;
		}
	}

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

	if (key != NULL && key->uids != NULL) {
		uids = malloc((spsize(key->uids) + 1) * sizeof (char *));
	
		curuid = key->uids;
		while (curuid != NULL) {
			buf[0] = 0;
			if (curuid->packet->tag == 13) {
				snprintf(buf, 1023, "%.*s",
						(int) curuid->packet->length,
						curuid->packet->data);
				uids[count++] = strdup(buf);
			}
			curuid = curuid -> next;
		}
		uids[count] = NULL;
	}
	/*
	 * TODO: Parse subpackets for real primary ID (v4 keys)
	 */
	if (primary != NULL) {
		*primary = uids[0];
	}

	return uids;
}
