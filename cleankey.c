/*
 * cleankey.c - Routines to look for common key problems and clean them up.
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
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "cleankey.h"
#include "keystructs.h"
#include "mem.h"
#include "merge.h"
#include "log.h"

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
 *	cleankeys - Apply all available cleaning options on a list of keys.
 *	@keys: The list of keys to clean.
 *
 *	Applies all the cleaning options we can (eg duplicate key ids) to a
 *	list of keys. Returns 0 if no changes were made, otherwise the number
 *	of keys cleaned.
 */
int cleankeys(struct openpgp_publickey *keys)
{
	int changed = 0;

	while (keys != NULL) {
		if (dedupuids(keys) > 0) {
			changed++;
		}
		keys = keys->next;
	}

	return changed;
}
