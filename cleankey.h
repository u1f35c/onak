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

#include "keydb.h"
#include "keystructs.h"

#define ONAK_CLEAN_CHECK_SIGHASH	(1 << 0)
#define ONAK_CLEAN_LARGE_PACKETS	(1 << 1)
#define ONAK_CLEAN_DROP_V3_KEYS		(1 << 2)
#define ONAK_CLEAN_UPDATE_ONLY		(1 << 3)
#define ONAK_CLEAN_VERIFY_SIGNATURES	(1 << 4)
#define ONAK_CLEAN_NEED_OTHER_SIG	(1 << 5)
#define ONAK_CLEAN_ALL			(uint64_t) -1

/**
 *	cleankeys - Apply all available cleaning options on a list of keys.
 *	@dbctx: A database context suitable for looking up signing keys
 *	@publickey: The list of keys to clean.
 *	@policies: The cleaning policies to apply.
 *
 *	Applies the requested cleaning policies to a list of keys. These are
 *	specified from the ONAK_CLEAN_* set of flags, or ONAK_CLEAN_ALL to
 *	apply all available cleaning options. Returns 0 if no changes were
 *	made, otherwise the number of keys cleaned. Note that some options
 *	may result in keys being removed entirely from the list.
 */
int cleankeys(struct onak_dbctx *dbctx, struct openpgp_publickey **keys,
		uint64_t policies);

#endif
