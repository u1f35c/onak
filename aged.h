/*
 * aged.h - Helpers to identify expired or aged-beyond-N keys.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mneme (u5=001777236237.945e_43.30_005.38) <mneme@foopgp.org>
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

#ifndef __AGED_H__
#define __AGED_H__

#include <stdbool.h>
#include <time.h>

#include "keydb.h"
#include "keystructs.h"

/**
 *	parse_age_string - Convert "25y" / "180d" / "12h" / "3600s" to seconds.
 *	@s: the age string. A bare integer is interpreted as years.
 *
 *	Returns the duration in seconds, or 0 if the input is empty,
 *	non-positive, or has an unrecognised suffix.
 */
time_t parse_age_string(const char *s);

/**
 *	key_creation_time - Read the primary key creation time.
 *	@key: the key to inspect.
 *
 *	Returns the timestamp held in bytes 1-4 of the public-key packet,
 *	or 0 if the key is malformed.
 */
time_t key_creation_time(struct openpgp_publickey *key);

/**
 *	key_expiration_time - Return the effective expiration of a key.
 *	@key: the key to inspect.
 *
 *	For v3 keys, reads the validity_days field. For v4+ keys, walks the
 *	hashed subpackets of every signature on every UID looking for the
 *	OPENPGP_SIGSUB_KEYEXPIRY subpacket (type 9), and returns the latest
 *	resulting absolute expiration time. Returns 0 if the key does not
 *	declare any expiration.
 */
time_t key_expiration_time(struct openpgp_publickey *key);

/**
 *	key_is_aged_or_expired - Predicate used by the aged-* commands.
 *	@key: the key under test.
 *	@now: the reference timestamp (typically time(NULL)).
 *	@max_age: a duration in seconds; 0 disables the age check.
 *
 *	Returns true when either the key is older than @max_age, or its
 *	declared expiration is in the past. Revoked keys are not treated
 *	specially: a revoked-but-not-yet-aged key returns false here.
 */
bool key_is_aged_or_expired(struct openpgp_publickey *key,
		time_t now, time_t max_age);

/**
 *	onak_cmd_aged - List fingerprints of expired or aged keys.
 *	onak_cmd_dump_aged - Emit a stream of expired or aged keys.
 *	onak_cmd_clean_aged - Delete expired or aged keys from the backend.
 *
 *	@dbctx: an open keydb context. The backend must implement
 *	        iterate_keys (and, for clean_aged, delete_key) for the
 *	        operation to actually do anything.
 *	@max_age: the age cutoff in seconds, 0 for "expired only".
 *	@binary: dump_aged only; if true the stream is raw OpenPGP,
 *	         otherwise it is ASCII armored.
 *
 *	Each returns the number of keys matched.
 */
int onak_cmd_aged(struct onak_dbctx *dbctx, time_t max_age);
int onak_cmd_dump_aged(struct onak_dbctx *dbctx, time_t max_age, bool binary);
int onak_cmd_clean_aged(struct onak_dbctx *dbctx, time_t max_age);

#endif
