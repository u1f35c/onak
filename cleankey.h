/*
 * cleankey.h - Routines to look for common key problems and clean them up.
 *
 * Copyright 2004 Jonathan McDowell <noodles@earth.li>
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
 * this program.  If not, see <https://www.gnu.org/licenses/>.
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
