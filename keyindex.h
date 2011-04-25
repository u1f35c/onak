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
 *	@skshash: List the sks hash?
 *	@html: Should we tailor the output for HTML?
 *
 *	This function takes a list of OpenPGP public keys and displays an index
 *	of them. Useful for debugging or the keyserver Index function.
 */
int key_index(struct openpgp_publickey *keys, bool verbose,
		bool fingerprint, bool skshash, bool html);

/**
 *	mrkey_index - List a set of OpenPGP keys in the MRHKP format.
 *	@keys: The keys to display.
 *
 *	This function takes a list of OpenPGP public keys and displays a
 *	machine readable list of them.
 */
int mrkey_index(struct openpgp_publickey *keys);
#endif
