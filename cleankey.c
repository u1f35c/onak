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
#include "openpgp.h"
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
	onak_status_t ret;
	uint8_t hashtype;
	uint8_t hash[64];
	uint8_t *sighash;
	int removed = 0;
	uint64_t keyid;

	while (*sigs != NULL) {
		ret = calculate_packet_sighash(key, sigdata, (*sigs)->packet,
				&hashtype, hash, &sighash);

		if (ret == ONAK_E_UNSUPPORTED_FEATURE) {
			get_keyid(key, &keyid);
			logthing(LOGTHING_ERROR,
				"Unsupported signature hash type %d on 0x%016"
				PRIX64,
				hashtype,
				keyid);
			sigs = &(*sigs)->next;
		} else if (ret != ONAK_E_OK ||
				!(hash[0] == sighash[0] &&
					hash[1] == sighash[1])) {
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

#define UAT_LIMIT	0xFFFF
#define UID_LIMIT	1024
#define PACKET_LIMIT	8383		/* Fits in 2 byte packet length */
int clean_large_packets(struct openpgp_publickey *key)
{
	struct openpgp_signedpacket_list **curuid = NULL;
	struct openpgp_signedpacket_list *tmp = NULL;
	bool                              drop;
	int                               dropped = 0;

	log_assert(key != NULL);
	curuid = &key->uids;
	while (*curuid != NULL) {
		drop = false;
		switch ((*curuid)->packet->tag) {
		case OPENPGP_PACKET_UID:
			if ((*curuid)->packet->length > UID_LIMIT)
				drop = true;
			break;
		case OPENPGP_PACKET_UAT:
			if ((*curuid)->packet->length > UAT_LIMIT)
				drop = true;
			break;
		default:
			if ((*curuid)->packet->length > PACKET_LIMIT)
				drop = true;
			break;
		}

		if (drop) {
			logthing(LOGTHING_INFO,
					"Dropping large (%d) packet, type %d",
					(*curuid)->packet->length,
					(*curuid)->packet->tag);
			/* Remove the entire large signed packet list */
			tmp = *curuid;
			*curuid = (*curuid)->next;
			tmp->next = NULL;
			free_signedpacket_list(tmp);
			dropped++;
		} else {
			curuid = &(*curuid)->next;
		}
	}

	return dropped;
}

/**
 *	cleankeys - Apply all available cleaning options on a list of keys.
 *	@policies: The cleaning policies to apply.
 *
 *	Applies the requested cleaning policies to a list of keys. These are
 *	specified from the ONAK_CLEAN_* set of flags, or ONAK_CLEAN_ALL to
 *	apply all available cleaning options. Returns 0 if no changes were
 *	made, otherwise the number of keys cleaned. Note that some options
 *	may result in keys being removed entirely from the list.
 */
int cleankeys(struct openpgp_publickey **keys, uint64_t policies)
{
	struct openpgp_publickey **curkey, *tmp;
	int changed = 0, count = 0;

	if (keys == NULL)
		return 0;

	curkey = keys;
	while (*curkey != NULL) {
		if (policies & ONAK_CLEAN_DROP_V3_KEYS) {
			if ((*curkey)->publickey->data[0] < 4) {
				/* Remove the key from the list */
				tmp = *curkey;
				*curkey = tmp->next;
				tmp->next = NULL;
				free_publickey(tmp);
				changed++;
				continue;
			}
		}
		if (policies & ONAK_CLEAN_LARGE_PACKETS) {
			count += clean_large_packets(*curkey);
		}
		count += dedupuids(*curkey);
		count += dedupsubkeys(*curkey);
		if (policies & ONAK_CLEAN_CHECK_SIGHASH) {
			count += clean_key_sighashes(*curkey);
		}
		if (count > 0) {
			changed++;
		}
		curkey = &(*curkey)->next;
	}

	return changed;
}
