/*
 * parsekey.h - Routines to parse an OpenPGP key.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#ifndef __PARSEKEY_H__
#define __PARSEKEY_H__

#include "keystructs.h"

/**
 *	add_key - Takes a key and adds it to the keyserver.
 *	@key: The public key to add.
 *
 *	This function takes a public key and adds it to the keyserver.
 *	It first of all sees if we already have the key locally. If we do then
 *	we retrieve it and merge the two keys. We then store the resulting key
 *	(or just the original we received if we don't already have it). We then
 *	send out the appropriate updates to our keyserver peers.
 */
int add_key(struct openpgp_publickey *key);

/**
 *	parse_keys - Process a stream of packets for public keys + sigs.
 *	@packets: The packet list to parse.
 *	@keys: The returned list of public keys.
 *
 *	This function takes an list of OpenPGP packets and attempts to parse it
 *	into a list of public keys with signatures and subkeys.
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
 *
 *	This function uses getchar_func to read characters from an OpenPGP
 *	packet stream and reads the packets into a linked list of packets
 *	ready for parsing as a public key or whatever.
 */
int read_openpgp_stream(int (*getchar_func)(void *ctx, size_t count,
				unsigned char *c),
				void *ctx,
				struct openpgp_packet_list **packets);

/**
 *	write_openpgp_stream - Reads a stream of OpenPGP packets.
 *	@putchar_func: The function to put the next character to the stream.
 *	@ctx: A pointer to the context structure for putchar_func.
 *	@packets: The list of packets.
 *
 *	This function uses putchar_func to write characters to an OpenPGP
 *	packet stream from a linked list of packets.
 */
int write_openpgp_stream(int (*putchar_func)(void *ctx, unsigned char c),
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
