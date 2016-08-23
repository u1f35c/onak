/*
 * parsekey.c - Routines to parse an OpenPGP key.
 *
 * Copyright 2002-2004,2007-2008,2011 Jonathan McDowell <noodles@earth.li>
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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyid.h"
#include "keystructs.h"
#include "ll.h"
#include "mem.h"
#include "onak.h"
#include "openpgp.h"
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
		case OPENPGP_PACKET_SIGNATURE:
			/*
			 * It's a signature packet. Add it to either the public
			 * key, to the current UID or the current subkey.
			 */
			if (curkey == NULL)
				return ONAK_E_INVALID_PARAM;
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
					sig,
					packet_dup(packets->packet));
				/*
				 * This is a signature on the public key; check
				 * if it's a revocation.
				 */
				if (packets->packet->data[0] == 3 &&
					packets->packet->data[2] ==
						OPENPGP_SIGTYPE_KEY_REV) {
					/*
					 * Type 3 key, 0x20 == revocation
					 */
					curkey->revoked = true;
				} else if (packets->packet->data[0] == 4 &&
					packets->packet->data[1] ==
						OPENPGP_SIGTYPE_KEY_REV) {
					/*
					 * Type 4 key, 0x20 == revocation
					 */
					curkey->revoked = true;
				}
			}
			break;
		case OPENPGP_PACKET_PUBLICKEY:
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
		case OPENPGP_PACKET_UID:
		case OPENPGP_PACKET_UAT:
			/*
			 * It's a UID packet (or a photo id, which is similar).
			 */
			if (curkey == NULL)
				return ONAK_E_INVALID_PARAM;
			if (curkey->subkeys != NULL)
				return ONAK_E_INVALID_PARAM;
			ADD_PACKET_TO_LIST_END(curkey,
				uid,
				packet_dup(packets->packet));
			break;
		case OPENPGP_PACKET_PUBLICSUBKEY:
			/*
			 * It's a subkey packet.
			 */
			if (curkey == NULL)
				return ONAK_E_INVALID_PARAM;
			ADD_PACKET_TO_LIST_END(curkey,
				subkey,
				packet_dup(packets->packet));
			break;
		case OPENPGP_PACKET_TRUST:
		case OPENPGP_PACKET_COMMENT:
			/*
			 * One of:
			 *
			 * Trust packet. Ignore.
			 * Comment packet. Ignore.
			 */
			break;
		default:
			/* Unsupported packet. Do what? Ignore for now. */
			break;
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
	printf("\tNew format: %d, Tag: %u, Length: %zd\n",
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
onak_status_t read_openpgp_stream(int (*getchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx,
				struct openpgp_packet_list **packets,
				int maxnum)
{
	unsigned char			 curchar = 0;
	struct openpgp_packet_list	*curpacket = NULL, **packetend = NULL;
	onak_status_t			 rc = ONAK_E_OK;
	int				 keys = 0;

	if (packets == NULL)
		return ONAK_E_INVALID_PARAM;

	curpacket = *packets;
	if (curpacket != NULL) {
		while (curpacket->next != NULL) {
			curpacket = curpacket->next;
		}
	}

	while (rc == ONAK_E_OK && (maxnum == 0 || keys < maxnum) &&
			!getchar_func(ctx, 1, &curchar)) {
		if (curchar & 0x80) {
			/*
			 * New packet. Allocate memory for it.
			 */
			if (curpacket != NULL) {
				curpacket->next = malloc(sizeof (*curpacket));
				packetend = &curpacket->next;
				curpacket = curpacket->next;
			} else {
				*packets = curpacket =
					malloc(sizeof (*curpacket));
				packetend = packets;
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
				if (getchar_func(ctx, 1, &curchar)) {
					rc = ONAK_E_INVALID_PKT;
					break;
				}
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
					free(curpacket->packet);
					curpacket->packet = NULL;
					rc = ONAK_E_UNSUPPORTED_FEATURE;
				} else if (curpacket->packet->length == 255) {
					/*
					 * 5 byte length; ie 255 followed by 3
					 * bytes of MSB length.
					 */
					if (getchar_func(ctx, 1, &curchar)) {
						rc = ONAK_E_INVALID_PKT;
						break;
					}
					curpacket->packet->length = curchar;
					curpacket->packet->length <<= 8;
					if (getchar_func(ctx, 1, &curchar)) {
						rc = ONAK_E_INVALID_PKT;
						break;
					}
					curpacket->packet->length += curchar;
					curpacket->packet->length <<= 8;
					if (getchar_func(ctx, 1, &curchar)) {
						rc = ONAK_E_INVALID_PKT;
						break;
					}
					curpacket->packet->length += curchar;
					curpacket->packet->length <<= 8;
					if (getchar_func(ctx, 1, &curchar)) {
						rc = ONAK_E_INVALID_PKT;
						break;
					}
					curpacket->packet->length += curchar;
				}
			} else {
				curpacket->packet->tag = (curchar & 0x3C) >> 2;
				switch (curchar & 3) {
				case 0:
					if (getchar_func(ctx, 1, &curchar)) {
						rc = ONAK_E_INVALID_PKT;
						break;
					}
					curpacket->packet->length = curchar;
					break;
				case 1:
					if (getchar_func(ctx, 1, &curchar)) {
						rc = ONAK_E_INVALID_PKT;
						break;
					}
					curpacket->packet->length = curchar;
					curpacket->packet->length <<= 8;
					if (getchar_func(ctx, 1, &curchar)) {
						rc = ONAK_E_INVALID_PKT;
						break;
					}
					curpacket->packet->length += curchar;
					break;
				case 2:
					if (getchar_func(ctx, 1, &curchar)) {
						rc = ONAK_E_INVALID_PKT;
						break;
					}
					curpacket->packet->length = 
						((unsigned) curchar << 24);
					if (getchar_func(ctx, 1, &curchar)) {
						rc = ONAK_E_INVALID_PKT;
						break;
					}
					curpacket->packet->length +=
						(curchar << 16);
					if (getchar_func(ctx, 1, &curchar)) {
						rc = ONAK_E_INVALID_PKT;
						break;
					}
					curpacket->packet->length +=
						(curchar << 8);
					if (getchar_func(ctx, 1, &curchar)) {
						rc = ONAK_E_INVALID_PKT;
						break;
					}
					curpacket->packet->length += curchar;
					break;
				case 3:
					rc = ONAK_E_UNSUPPORTED_FEATURE;
					free(curpacket->packet);
					curpacket->packet = NULL;
					break;
				}
			}

			if (rc == 0) {
				if (curpacket->packet->tag ==
						OPENPGP_PACKET_PUBLICKEY) {
					keys++;
				}
				curpacket->packet->data =
					malloc(curpacket->packet->length *
					sizeof(unsigned char));
				if (curpacket->packet->data == NULL) {
					rc = ONAK_E_NOMEM;
				} else {
					rc = getchar_func(ctx,
						curpacket->packet->length,
						curpacket->packet->data);
				}
			}
		} else {
			rc = ONAK_E_INVALID_PKT;
		}
		if (rc == ONAK_E_OK) {
			/* Make sure the packet version is sane */
			switch (curpacket->packet->tag) {
			case OPENPGP_PACKET_ENCRYPTED_MDC:
				/* These packets must be v1 */
				if (curpacket->packet->data[0] != 1) {
					rc = ONAK_E_INVALID_PKT;
				}
				break;
			case OPENPGP_PACKET_PKSESSIONKEY:
			case OPENPGP_PACKET_ONEPASSSIG:
				/* These packets must be v3 */
				if (curpacket->packet->data[0] != 3) {
					rc = ONAK_E_INVALID_PKT;
				}
				break;
			case OPENPGP_PACKET_SYMSESSIONKEY:
				/* These packets must be v4 */
				if (curpacket->packet->data[0] != 4) {
					rc = ONAK_E_INVALID_PKT;
				}
				break;
			case OPENPGP_PACKET_SIGNATURE:
			case OPENPGP_PACKET_SECRETKEY:
			case OPENPGP_PACKET_PUBLICKEY:
				/* Must be v2 -> v4 */
				if (curpacket->packet->data[0] < 2 ||
					curpacket->packet->data[0] > 4) {
					rc = ONAK_E_INVALID_PKT;
				}
				break;
			default:
				break;
			}
		}
	}

	if (packetend != NULL) {
		if ((*packetend)->packet != NULL) {
			/* If we got an invalid final packet, discard it. */
			if ((*packetend)->packet->data != NULL &&
					rc != ONAK_E_OK) {
				free((*packetend)->packet->data);
				(*packetend)->packet->data = NULL;
			}
			/* If we didn't get any data, clean it up. */
			if ((*packetend)->packet->data == NULL) {
				free((*packetend)->packet);
				(*packetend)->packet = NULL;
			}
		}
		/* Trim the last packet if it doesn't actually exist */
		if ((*packetend)->packet == NULL) {
			free(*packetend);
			*packetend = NULL;
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
onak_status_t write_openpgp_stream(int (*putchar_func)(void *ctx, size_t count,
						void *c),
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
			} else if (packets->packet->length > 8382 &&
				packets->packet->length < 0xFFFFFFFF) {
				curchar = 255;
				putchar_func(ctx, 1, &curchar);
				
				curchar = (packets->packet->length >> 24);
				curchar &= 0xFF;
				putchar_func(ctx, 1, &curchar);
				
				curchar = (packets->packet->length >> 16);
				curchar &= 0xFF;
				putchar_func(ctx, 1, &curchar);
				
				curchar = (packets->packet->length >> 8);
				curchar &= 0xFF;
				putchar_func(ctx, 1, &curchar);
				
				curchar = packets->packet->length;
				curchar &= 0xFF;
				putchar_func(ctx, 1, &curchar);
			} else {
				return ONAK_E_UNSUPPORTED_FEATURE;
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

	return ONAK_E_OK;
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
		 * Now do any signatures on the main key.
		 */
		for (tmplist = key->sigs; tmplist != NULL;
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
