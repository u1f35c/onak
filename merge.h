/*
 * merge.h - Routines to merge OpenPGP public keys.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#ifndef __MERGE_H__

#include "keystructs.h"

/**
 *	merge_keys - Takes 2 public keys and merges them.
 *	@a: The old key. The merged key is returned in this structure.
 *	@b: The new key. The changed from old to new keys are returned in this
 *		structure.
 *
 *	This function takes 2 keys and merges them. It then returns the merged
 *	key in a and the difference between this new key and the original a
 *	in b (ie newb contains the minimum amount of detail necessary to
 *	convert olda to newa). The intention is that olda is provided from
 *	internal storage and oldb from the remote user. newa is then stored in
 *	internal storage and newb is sent to all our keysync peers.
 */
int merge_keys(struct openpgp_publickey *a, struct openpgp_publickey *b);

#endif
