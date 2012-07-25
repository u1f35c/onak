/*
 * parsekey.h - Routines to parse an OpenPGP key.
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

#ifndef __PARSEKEY_H__
#define __PARSEKEY_H__

#include "keystructs.h"
#include "onak.h"

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
		struct openpgp_publickey **keys);

/**
 *	debug_packet - Print debug info about a packet
 *	@packet: The packet to display.
 *
 *	This function takes an OpenPGP packet and displays some information
 *	about it to stdout. Useful for debugging purposes or curiousity about
 *	an OpenPGP packet stream.
 */
int debug_packet(struct openpgp_packet *packet);

/**
 *	read_openpgp_stream - Reads a stream of OpenPGP packets.
 *	@getchar_func: The function to get the next character from the stream.
 *	@ctx: A pointer to the context structure for getchar_func.
 *	@packets: The outputted list of packets.
 *	@maxnum: The maximum number of keys to read. 0 means unlimited.
 *
 *	This function uses getchar_func to read characters from an OpenPGP
 *	packet stream and reads the packets into a linked list of packets
 *	ready for parsing as a public key or whatever. maxnum allows you to
 *	specify the maximum number of keys to read. Note that if this is used
 *	then only the public key component of the last key will be returned,
 *	none of the other packets of the key will be read.
 */
onak_status_t read_openpgp_stream(int (*getchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx,
				struct openpgp_packet_list **packets,
				int maxnum);

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
				struct openpgp_packet_list *packets);

/**
 *	flatten_publickey - Convert a publickey to an OpenPGP packet list.
 *	@key: The public key.
 *	@packets: The outputted packet list.
 *	@list_end: The end of the packet list.
 *
 *	This function converts public key structure to a linked list of OpenPGP
 *	packets ready for outputing or storage. If we're not appending to an
 *	existing list then both packets & list_end will be pointers to NULLs,
 *	other wise packets should point to the start of the list and list_end
 *	to the end so we can append to the end.
 */
int flatten_publickey(struct openpgp_publickey *key,
			struct openpgp_packet_list **packets,
			struct openpgp_packet_list **list_end);

#endif /* __PARSEKEY_H__ */
