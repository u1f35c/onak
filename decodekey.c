/*
 * decodekey.c - Routines to further decode an OpenPGP key.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "decodekey.h"
#include "hash.h"
#include "keyid.h"
#include "keystructs.h"
#include "ll.h"
#include "log.h"

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

	log_assert(data != NULL);

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
		switch (data[offset] & 0x7F) {
		case 2:
			/*
			 * Signature creation time. Might want to output this?
			 */
			break;
		case 3:
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
		case 20:
			/*
			 * Annotation data.
			 */
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
			 * 7 is set in which case we log a major error.
			 */
			if (data[offset] & 0x80) {
				logthing(LOGTHING_CRITICAL,
				"Critical subpacket type not parsed: 0x%X",
					data[offset]);
			}
				
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
        
        if (primary != NULL) {
        	*primary = NULL;
	}

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
uint64_t *keysubkeys(struct openpgp_publickey *key)
{
	struct openpgp_signedpacket_list *cursubkey = NULL;
	uint64_t                         *subkeys = NULL;
	int                               count = 0;
        
	if (key != NULL && key->subkeys != NULL) {
		subkeys = malloc((spsize(key->subkeys) + 1) *
				sizeof (uint64_t));
		cursubkey = key->subkeys;
		while (cursubkey != NULL) {
			subkeys[count++] = get_packetid(cursubkey->packet);
			cursubkey = cursubkey -> next;
		}
		subkeys[count] = 0;
	}

	return subkeys;
}
