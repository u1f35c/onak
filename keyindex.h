/*
 * keyindex.h - Routines to list an OpenPGP key.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#ifndef __KEYINDEX_H__
#define __KEYINDEX_H__

#include <stdbool.h>

#include "keystructs.h"

/**
 *	key_index - List a set of OpenPGP keys.
 *	@keys: The keys to display.
 *      @verbose: Should we list sigs as well?
 *	@fingerprint: List the fingerprint?
 *	@html: Should we tailor the output for HTML?
 *
 *	This function takes a list of OpenPGP public keys and displays an index
 *	of them. Useful for debugging or the keyserver Index function.
 */
int key_index(struct openpgp_publickey *keys, bool verbose,
		bool fingerprint, bool html);

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

#endif
