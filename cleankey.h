/*
 * cleankey.h - Routines to look for common key problems and clean them up.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2004 Project Purple
 */

#ifndef __CLEANKEY_H__
#define __CLEANKEY_H__

#include "keystructs.h"

/**
 *	cleankeys - Apply all available cleaning options on a list of keys.
 *	@publickey: The list of keys to clean.
 *
 *	Applies all the cleaning options we can (eg duplicate key ids) to a
 *	list of keys. Returns 0 if no changes were made, otherwise the number
 *	of keys cleaned.
 */
int cleankeys(struct openpgp_publickey *keys);

#endif
