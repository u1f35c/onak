/*
 * keyindex.h - Routines to list an OpenPGP key.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 *
 * $Id: decodekey.h,v 1.2 2003/06/04 20:57:07 noodles Exp $
 */

#ifndef __DECODEKEY_H__
#define __DECODEKEY_H__

#include "keystructs.h"
#include "ll.h"

/**
 *	keysigs - Return the sigs on a given OpenPGP signature packet list.
 *	@curll: The current linked list. Can be NULL to create a new list.
 *	@sigs: The signature list we want the sigs on.
 *
 *	Returns a linked list of stats_key elements containing the sigs for the
 *	supplied OpenPGP signature packet list.
 */
struct ll *keysigs(struct ll *curll,
		struct openpgp_packet_list *sigs);

/**
 *	sig_keyid - Return the keyid for a given OpenPGP signature packet.
 *	@packet: The signature packet.
 *
 *	Returns the keyid for the supplied signature packet.
 */
uint64_t sig_keyid(struct openpgp_packet *packet);

/**
 *	keyuids - Takes a key and returns an array of its UIDs
 *	@key: The key to get the uids of.
 *	@primary: A pointer to store the primary UID in.
 *
 *	keyuids takes a public key structure and builds an array of the UIDs 
 *	on the key. It also attempts to work out the primary UID and returns a
 *	separate pointer to that particular element of the array.
 */
char **keyuids(struct openpgp_publickey *key, char **primary);

/**
 *	keysubkeys - Takes a key and returns an array of its subkey keyids.
 *	@key: The key to get the subkeys of.
 *
 *	keysubkeys takes a public key structure and returns an array of the
 *	subkey keyids for that key.
 */
uint64_t *keysubkeys(struct openpgp_publickey *key);

#endif
