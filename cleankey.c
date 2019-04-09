/*
 * cleankey.c - Routines to look for common key problems and clean them up.
 *
 * Copyright 2004,2012 Jonathan McDowell <noodles@earth.li>
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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "cleankey.h"
#include "keyid.h"
#include "keystructs.h"
#include "log.h"
#include "mem.h"
#include "merge.h"
#include "onak-conf.h"
#include "sigcheck.h"

/**
 *	dedupuids - Merge duplicate uids on a key.
 *	@key: The key to de-dup uids on.
 *
 *	This function attempts to merge duplicate IDs on a key. It returns 0
 *	if the key is unchanged, otherwise the number of dups merged.
 */
int dedupuids(struct openpgp_publickey *key)
{
	struct openpgp_signedpacket_list *curuid = NULL;
	struct openpgp_signedpacket_list *dup = NULL;
	struct openpgp_signedpacket_list *tmp = NULL;
	int                               merged = 0;

	log_assert(key != NULL);
	curuid = key->uids;
	while (curuid != NULL) {
		dup = find_signed_packet(curuid->next, curuid->packet);
		while (dup != NULL) {
			logthing(LOGTHING_INFO, "Found duplicate uid: %.*s",
					curuid->packet->length,
					curuid->packet->data);
			merged++;
			merge_packet_sigs(curuid, dup);
			/*
			 * Remove the duplicate uid.
			 */
			tmp = curuid;
			while (tmp != NULL && tmp->next != dup) {
				tmp = tmp->next;
			}
			log_assert(tmp != NULL);
			tmp->next = dup->next;
			dup->next = NULL;
			free_signedpacket_list(dup);

			dup = find_signed_packet(curuid->next, curuid->packet);
		}
		curuid = curuid->next;
	}

	return merged;
}

/**
 *	dedupsubkeys - Merge duplicate subkeys on a key.
 *	@key: The key to de-dup subkeys on.
 *
 *	This function attempts to merge duplicate subkeys on a key. It returns
 *	0 if the key is unchanged, otherwise the number of dups merged.
 */
int dedupsubkeys(struct openpgp_publickey *key)
{
	struct openpgp_signedpacket_list *cursubkey = NULL;
	struct openpgp_signedpacket_list *dup = NULL;
	struct openpgp_signedpacket_list *tmp = NULL;
	int                               merged = 0;
	uint64_t                          subkeyid;

	log_assert(key != NULL);
	cursubkey = key->subkeys;
	while (cursubkey != NULL) {
		dup = find_signed_packet(cursubkey->next, cursubkey->packet);
		while (dup != NULL) {
			get_packetid(cursubkey->packet, &subkeyid);
			logthing(LOGTHING_INFO,
				"Found duplicate subkey: 0x%016" PRIX64,
				subkeyid);
			merged++;
			merge_packet_sigs(cursubkey, dup);
			/*
			 * Remove the duplicate uid.
			 */
			tmp = cursubkey;
			while (tmp != NULL && tmp->next != dup) {
				tmp = tmp->next;
			}
			log_assert(tmp != NULL);
			tmp->next = dup->next;
			dup->next = NULL;
			free_signedpacket_list(dup);

			dup = find_signed_packet(cursubkey->next,
				cursubkey->packet);
		}
		cursubkey = cursubkey->next;
	}

	return merged;
}

/**
 *	check_sighashes - Check that sig hashes are correct.
 *	@key - the check to check the sig hashes of.
 *
 *	Given an OpenPGP key confirm that all of the sigs on it have the
 *	appropriate 2 octet hash beginning, as stored as part of the sig.
 *	This is a simple way to remove junk sigs and, for example, catches
 *	subkey sig corruption as produced by old pksd implementations.
 *	Any sig that has an incorrect hash is removed from the key. If the
 *	hash cannot be checked (eg we don't support that hash type) we err
 *	on the side of caution and keep it.
 */
int clean_sighashes(struct openpgp_publickey *key,
		struct openpgp_packet *sigdata,
		struct openpgp_packet_list **sigs)
{
	struct openpgp_packet_list *tmpsig;
	int removed = 0;

	while (*sigs != NULL) {
		if (check_packet_sighash(key, sigdata, (*sigs)->packet) == 0) {
			tmpsig = *sigs;
			*sigs = (*sigs)->next;
			tmpsig->next = NULL;
			free_packet_list(tmpsig);
			removed++;
		} else {
			sigs = &(*sigs)->next;
		}
	}

	return removed;
}

int clean_list_sighashes(struct openpgp_publickey *key,
			struct openpgp_signedpacket_list *siglist)
{
	int removed = 0;

	while (siglist != NULL) {
		removed += clean_sighashes(key, siglist->packet,
			&siglist->sigs);
		siglist = siglist->next;
	}

	return removed;
}

int clean_key_sighashes(struct openpgp_publickey *key)
{
	int removed;

	removed = clean_sighashes(key, NULL, &key->sigs);
	removed += clean_list_sighashes(key, key->uids);
	removed += clean_list_sighashes(key, key->subkeys);

	return removed;
}

/**
 *	cleankeys - Apply all available cleaning options on a list of keys.
 *	@keys: The list of keys to clean.
 *
 *	Applies all the cleaning options we can (eg duplicate key ids) to a
 *	list of keys. Returns 0 if no changes were made, otherwise the number
 *	of keys cleaned.
 */
int cleankeys(struct openpgp_publickey *keys)
{
	int changed = 0, count;

	while (keys != NULL) {
		count = dedupuids(keys);
		count += dedupsubkeys(keys);
		if (config.check_sighash) {
			count += clean_key_sighashes(keys);
		}
		if (count > 0) {
			changed++;
		}
		keys = keys->next;
	}

	return changed;
}
