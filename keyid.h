/*
 * keyid.h - Routines to calculate key IDs.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#ifndef __KEYID_H__
#define __KEYID_H__

// #include <stdint.h>
#include <inttypes.h>

#include "keystructs.h"

/**
 *	get_keyid - Given a public key returns the keyid.
 *	@publickey: The key to calculate the fingerprint for.
 *
 *	This function returns the key id for a given public key.
 */
uint64_t get_keyid(struct openpgp_publickey *publickey);

#endif /* __KEYID_H__ */
