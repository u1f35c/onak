/*
 * parsekey.c - Routines to parse an OpenPGP key.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 *
 * $Id: parsekey.c,v 1.17 2003/10/11 21:52:18 noodles Exp $
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyid.h"
#include "keystructs.h"
#include "ll.h"
#include "log.h"
#include "mem.h"
#include "parsekey.h"

/**
 *	parse_keys - Process a stream of packets for public keys + sigs.
 *	@packets: The packet list to parse.
 *	@keys: The returned list of public keys.
 *
 *	This function takes an list of OpenPGP packets and attempts to parse it
 *	into a list of public keys with signatures and subkeys.
 *
 *      Returns a count of how many keys we parsed.
 */
int parse_keys(struct openpgp_packet_list *packets,
		struct openpgp_publickey **keys)
{
	struct openpgp_publickey *curkey = NULL;
	int count;

	count = 0;

	/*
	 * If keys already has some keys in it then set curkey to the last one
	 * so we add to the end of the list.
	 */
	for (curkey = *keys; curkey != NULL && curkey->next != NULL;
			curkey = curkey->next) ;

	while (packets != NULL) {
		switch (packets->packet->tag) {
		case 2:
			/*
			 * It's a signature packet. Add it to either the public
			 * key (it should be a revocation), to the current UID
			 * or the current subkey.
			 */
			assert(curkey != NULL);
			if (curkey->subkeys != NULL) {
				ADD_PACKET_TO_LIST_END(curkey->last_subkey,
					sig,
					packet_dup(packets->packet));
			} else if (curkey->uids != NULL) {
				ADD_PACKET_TO_LIST_END(curkey->last_uid,
					sig,
					packet_dup(packets->packet));
			} else {
				ADD_PACKET_TO_LIST_END(curkey,
					revocation,
					packet_dup(packets->packet));
			}
			break;
		case 6:
			/*
			 * It's a public key packet, so start a new key in our
			 * list.
			 */
			if (curkey != NULL) {
				curkey->next = malloc(sizeof (*curkey));
				curkey = curkey->next;
			} else {
				*keys = curkey =
					malloc(sizeof (*curkey));
			}
			memset(curkey, 0, sizeof(*curkey));
			curkey->publickey = packet_dup(packets->packet);
			count++;
			break;
		case 13:
		case 17:
			/*
			 * It's a UID packet (or a photo id, which is similar).
			 */
			assert(curkey != NULL);
			assert(curkey->subkeys == NULL);
			ADD_PACKET_TO_LIST_END(curkey,
				uid,
				packet_dup(packets->packet));
			break;
		case 14:
			/*
			 * It's a subkey packet.
			 */
			assert(curkey != NULL);
			ADD_PACKET_TO_LIST_END(curkey,
				subkey,
				packet_dup(packets->packet));
			break;
		case 12:
		case 61:
			/*
			 * One of:
			 *
			 * Trust packet. Ignore.
			 * Comment packet. Ignore.
			 */
			break;
		default:
			logthing(LOGTHING_ERROR,
					"Unsupported packet type: %d",
					packets->packet->tag);
		}
		packets = packets->next;
	}

	return count;
}

/**
 *	debug_packet - Print debug info about a packet
 *	@packet: The packet to display.
 *
 *	This function takes an OpenPGP packet and displays some information
 *	about it to stdout. Useful for debugging purposes or curiousity about
 *	an OpenPGP packet stream.
 */
int debug_packet(struct openpgp_packet *packet)
{
	printf("\tNew format: %d, Tag: %u, Length: %d\n",
			packet->newformat,
			packet->tag,
			packet->length);

	return 0;
}

/**
 *	read_openpgp_stream - Reads a stream of OpenPGP packets.
 *	@getchar_func: The function to get the next character from the stream.
 *	@ctx: A pointer to the context structure for getchar_func.
 *	@packets: The outputted list of packets.
 *	@maxnum: The maximum number of keys to read. 0 means unlimited.
 *
 *	This function uses getchar_func to read characters from an OpenPGP
 *	packet stream and reads the packets into a linked list of packets
 *	ready for parsing as a public key or whatever.
 */
int read_openpgp_stream(int (*getchar_func)(void *ctx, size_t count,
				unsigned char *c),
				void *ctx,
				struct openpgp_packet_list **packets,
				int maxnum)
{
	unsigned char			 curchar = 0;
	struct openpgp_packet_list	*curpacket = NULL;
	int				 rc = 0;
	int				 keys = 0;
	bool				 inpacket = false;

	assert(packets != NULL);
	curpacket = *packets;
	if (curpacket != NULL) {
		while (curpacket->next != NULL) {
			curpacket = curpacket->next;
		}
	}

	while (!rc && (maxnum == 0 || keys < maxnum) &&
			!getchar_func(ctx, 1, &curchar)) {
		if (!inpacket && (curchar & 0x80)) {
			/*
			 * New packet. Record the fact we're in a packet and
			 * allocate memory for it.
			 */
			inpacket = true;
			if (curpacket != NULL) {
				curpacket->next = malloc(sizeof (*curpacket));
				curpacket = curpacket->next;
			} else {
				*packets = curpacket =
					malloc(sizeof (*curpacket));
			}
			memset(curpacket, 0, sizeof(*curpacket));
			curpacket->packet =
				malloc(sizeof (*curpacket->packet));
			memset(curpacket->packet, 0,
					sizeof(*curpacket->packet));

			curpacket->packet->newformat = (curchar & 0x40);

			/*
			 * TODO: Better error checking on getchar_func.
			 */
			if (curpacket->packet->newformat) {
				curpacket->packet->tag = (curchar & 0x3F);
				rc = getchar_func(ctx, 1, &curchar);
				curpacket->packet->length = curchar;
				if (curpacket->packet->length > 191 &&
					curpacket->packet->length < 224) {
					rc = getchar_func(ctx, 1, &curchar);
					curpacket->packet->length -= 192;
					curpacket->packet->length <<= 8;
					curpacket->packet->length += curchar;
					curpacket->packet->length += 192;
				} else if (curpacket->packet->length > 223 &&
					curpacket->packet->length < 255) {
					logthing(LOGTHING_NOTICE,
						"Partial length;"
						" not supported.");
				} else if (curpacket->packet->length == 255) {
					/*
					 * 5 byte length; ie 255 followed by 3
					 * bytes of MSB length.
					 */
					rc = getchar_func(ctx, 1, &curchar);
					curpacket->packet->length = curchar;
					curpacket->packet->length <<= 8;
					rc = getchar_func(ctx, 1, &curchar);
					curpacket->packet->length = curchar;
					curpacket->packet->length <<= 8;
					rc = getchar_func(ctx, 1, &curchar);
					curpacket->packet->length = curchar;
					curpacket->packet->length <<= 8;
					rc = getchar_func(ctx, 1, &curchar);
					curpacket->packet->length = curchar;
				}
			} else {
				curpacket->packet->tag = (curchar & 0x3C) >> 2;
				switch (curchar & 3) {
				case 0:
					rc = getchar_func(ctx, 1, &curchar);
					curpacket->packet->length = curchar;
					break;
				case 1:
					rc = getchar_func(ctx, 1, &curchar);
					curpacket->packet->length = curchar;
					curpacket->packet->length <<= 8;
					rc = getchar_func(ctx, 1, &curchar);
					curpacket->packet->length += curchar;
					break;
				case 2:
					rc = getchar_func(ctx, 1, &curchar);
					curpacket->packet->length = 
						(curchar << 24);
					rc = getchar_func(ctx, 1, &curchar);
					curpacket->packet->length +=
						(curchar << 16);
					rc = getchar_func(ctx, 1, &curchar);
					curpacket->packet->length +=
						(curchar << 8);
					rc = getchar_func(ctx, 1, &curchar);
					curpacket->packet->length += curchar;
					break;
				case 3:
					logthing(LOGTHING_ERROR,
						"Unsupported length type 3.");
					curpacket->packet->length = 0;
					curpacket->packet->data = NULL;
					rc = -1;
					break;
				}
			}

			if (rc == 0) {
				if (curpacket->packet->tag == 6) {
					keys++;
				}
				curpacket->packet->data =
					malloc(curpacket->packet->length *
					sizeof(unsigned char));
				if (curpacket->packet->data == NULL) {
					logthing(LOGTHING_ERROR, 
						"Can't allocate memory for "
						"packet!");
					rc = -1;
				} else {
					rc = getchar_func(ctx,
						curpacket->packet->length,
						curpacket->packet->data);
				}
			}
			inpacket = false;
		} else {
			logthing(LOGTHING_ERROR, "Unexpected character: 0x%X",
				curchar);
		}
	}

	return (rc);
}

/**
 *	write_openpgp_stream - Reads a stream of OpenPGP packets.
 *	@putchar_func: The function to put the next character to the stream.
 *	@ctx: A pointer to the context structure for putchar_func.
 *	@packets: The list of packets.
 *
 *	This function uses putchar_func to write characters to an OpenPGP
 *	packet stream from a linked list of packets.
 */
int write_openpgp_stream(int (*putchar_func)(void *ctx, size_t count,
						unsigned char *c),
				void *ctx,
				struct openpgp_packet_list *packets)
{
	unsigned char	curchar = 0;

	while (packets != NULL) {
		curchar = 0x80;
		if (packets->packet->newformat) {
			curchar |= 0x40;
			curchar |= packets->packet->tag;
			putchar_func(ctx, 1, &curchar);

			if (packets->packet->length < 192) {
				curchar = packets->packet->length;
				putchar_func(ctx, 1, &curchar);
			} else if (packets->packet->length > 191 &&
				packets->packet->length < 8383) {
				curchar = (((packets->packet->length - 192) &
					 0xFF00) >> 8) + 192;
				putchar_func(ctx, 1, &curchar);

				curchar = (packets->packet->length - 192) &
					 0xFF;
				putchar_func(ctx, 1, &curchar);
			} else {
				logthing(LOGTHING_ERROR,
					"Unsupported new format length.");
			}
		} else {
			curchar |= (packets->packet->tag << 2);
			if (packets->packet->length < 256) {
				putchar_func(ctx, 1, &curchar);
				curchar = packets->packet->length;
				putchar_func(ctx, 1, &curchar);
			} else if (packets->packet->length < 0x10000) {
				curchar |= 1;
				putchar_func(ctx, 1, &curchar);
				curchar = packets->packet->length >> 8;
				putchar_func(ctx, 1, &curchar);
				curchar = packets->packet->length & 0xFF;
				putchar_func(ctx, 1, &curchar);
			} else {
				curchar |= 2;
				putchar_func(ctx, 1, &curchar);
				curchar = packets->packet->length >> 24;
				putchar_func(ctx, 1, &curchar);
				curchar = (packets->packet->length >> 16) & 0xFF;
				putchar_func(ctx, 1, &curchar);
				curchar = (packets->packet->length >> 8) & 0xFF;
				putchar_func(ctx, 1, &curchar);
				curchar = packets->packet->length & 0xFF;
				putchar_func(ctx, 1, &curchar);
			}
		}

		putchar_func(ctx, packets->packet->length,
				packets->packet->data);
		packets = packets->next;
	}
	return 0;
}

/**
 *	flatten_publickey - Convert a publickey to an OpenPGP packet list.
 *	@key: The public key.
 *	@packets: The outputted packet list.
 *
 *	This function converts public key structure to a linked list of OpenPGP
 *	packets ready for outputing or storage.
 */
int flatten_publickey(struct openpgp_publickey *key,
			struct openpgp_packet_list **packets,
			struct openpgp_packet_list **list_end)
{
	struct openpgp_signedpacket_list	*tmpsignedlist = NULL;
	struct openpgp_packet_list		*tmplist = NULL;

	while (key != NULL) {
		/*
		 * First write the public key packet out.
		 */
		ADD_PACKET_TO_LIST((*list_end), packet_dup(key->publickey));
		if (*packets == NULL) {
			*packets = *list_end;
		}

		/*
		 * Now do any revocation signatures on the main key.
		 */
		for (tmplist = key->revocations; tmplist != NULL;
				tmplist = tmplist->next) {
			ADD_PACKET_TO_LIST((*list_end),
					packet_dup(tmplist->packet));
		}

		/*
		 * Output any UIDs along with their signatures.
		 */
		for (tmpsignedlist = key->uids; tmpsignedlist != NULL;
				tmpsignedlist = tmpsignedlist->next) {

			ADD_PACKET_TO_LIST((*list_end),
				packet_dup(tmpsignedlist->packet));
			for (tmplist = tmpsignedlist->sigs; tmplist != NULL;
					tmplist = tmplist->next) {
				ADD_PACKET_TO_LIST((*list_end), 
					packet_dup(tmplist->packet));
			}
		}

		/*
		 * Output any subkeys along with their signatures.
		 */
		for (tmpsignedlist = key->subkeys; tmpsignedlist != NULL;
				tmpsignedlist = tmpsignedlist->next) {

			ADD_PACKET_TO_LIST((*list_end),
				packet_dup(tmpsignedlist->packet));
			for (tmplist = tmpsignedlist->sigs; tmplist != NULL;
					tmplist = tmplist->next) {
				ADD_PACKET_TO_LIST((*list_end), 
					packet_dup(tmplist->packet));
			}
		}
		key = key->next;
	}
	return 0;
}
