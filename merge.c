/*
 * merge.c - Routines to merge OpenPGP public keys.
 *
 * Copyright 2002-2005,2007,2011 Jonathan McDowell <noodles@earth.li>
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decodekey.h"
#include "keyid.h"
#include "keystructs.h"
#include "ll.h"
#include "mem.h"
#include "merge.h"
#include "onak.h"

/**
 *	compare_packets - Check to see if 2 OpenPGP packets are the same.
 *	@a: The first packet to compare.
 *	@b: The second packet to compare.
 *
 *	Takes 2 packets and returns 0 if they are the same, -1 if a is
 *      less than b, or 1 if a is greater than b.
 */
int compare_packets(struct openpgp_packet *a, struct openpgp_packet *b)
{
	int ret, len;

	if (a->tag > b->tag) {
		ret = 1;
	} else if (b->tag > a->tag) {
		ret = -1;
	} else {
		len = (a->length < b->length) ? a->length : b->length;
		ret = memcmp(a->data, b->data, len);
		if (ret == 0 && a->length != b->length) {
			ret = (a->length < b->length) ? -1 : 1;
		}
	}

	return ret;
}

/**
 *	compare_signatures - Check to see if 2 OpenPGP signatures are the same.
 *	@a: The first signature to compare.
 *	@b: The second signature to compare.
 *
 *	Takes 2 signature packets and returns true if they are the same and
 *	false otherwise.
 */
bool compare_signatures(struct openpgp_packet *a, struct openpgp_packet *b)
{
	uint64_t a_keyid, b_keyid;
	time_t a_creation, b_creation;

	if (a->data[0] != b->data[0]) {
		/* Different signature versions, so not the same */
		return false;
	} else if (a->data[0] == 4 && a->data[1] != b->data[1]) {
		/* Type 4 signature, but different types */
		return false;
	} else {
		sig_info(a, &a_keyid, &a_creation);
		sig_info(b, &b_keyid, &b_creation);
		return (a_creation == b_creation) && (a_keyid == b_keyid);
	}
}

/**
 *	find_packet - Checks to see if an OpenPGP packet exists in a list.
 *	@packet_list: The list of packets to look in.
 *	@packet: The packet to look for.
 *
 *	Walks through the packet_list checking to see if the packet given is
 *	present in it. Returns true if it is.
 */
bool find_packet(struct openpgp_packet_list *packet_list,
			struct openpgp_packet *packet)
{
	bool found = false;

	while (!found && packet_list != NULL) {
		if (compare_packets(packet_list->packet, packet) == 0) {
			found = true;
		}
		packet_list = packet_list -> next;
	}

	return found;
}

/**
 *	find_signature - Checks to see if an OpenPGP signature exists in a list.
 *	@packet_list: The list of packets to look in.
 *	@packet: The signature to look for.
 *
 *	Walks through the packet_list checking to see if the signature given is
 *	present in it. Returns a pointer to it if it is, NULL otherwise.
 *
 */
struct openpgp_packet_list *find_signature(
			struct openpgp_packet_list *packet_list,
			struct openpgp_packet *packet)
{
	struct openpgp_packet_list *found = NULL;

	while (!found && packet_list != NULL) {
		if (compare_signatures(packet_list->packet, packet)) {
			found = packet_list;
		}
		packet_list = packet_list -> next;
	}

	return found;
}

/**
 *	get_signed_packet - Gets a signed packet from a list.
 *	@packet_list: The list of packets to look in.
 *	@packet: The packet to look for.
 *
 *	Walks through the signedpacket_list looking for the supplied packet and
 *	returns it if found. Otherwise returns NULL.
 */
struct openpgp_signedpacket_list *find_signed_packet(
		struct openpgp_signedpacket_list *packet_list,
		struct openpgp_packet *packet)
{
	struct openpgp_signedpacket_list *found = NULL;

	while (found == NULL && packet_list != NULL) {
		if (compare_packets(packet_list->packet, packet) == 0) {
			found = packet_list;
		}
		packet_list = packet_list -> next;
	}

	return found;
}

/**
 *	remove_signed_packet - Removes a signed packet from a list.
 *	@packet_list: The list of packets to look in.
 *	@packet: The packet to remove.
 *
 *	Walks through the signedpacket_list looking for the supplied packet and
 *	removes it if found. Assumes the packet can only exist a maximum of
 *	once in the list.
 */
static void remove_signed_packet(struct openpgp_signedpacket_list **packet_list,
		struct openpgp_signedpacket_list **list_end,
		struct openpgp_packet *packet)
{
	struct openpgp_signedpacket_list *cur = NULL;
	struct openpgp_signedpacket_list *prev = NULL;

	for (cur = *packet_list; cur != NULL; cur = cur->next) {
		if (compare_packets(cur->packet, packet) == 0) {
			if (prev == NULL) {
				*packet_list = cur->next;
			} else {
				prev->next = cur->next;
			}
			if (cur->next == NULL) {
				*list_end = prev;
			}
			cur->next = NULL;
			free_signedpacket_list(cur);
			break;
		}
		prev = cur;
	}

	return;
}

/**
 *	merge_packet_sigs - Takes 2 signed packets and merges their sigs.
 *	@old: The old signed packet.
 *	@new: The new signed packet.
 *
 *	Takes 2 signed packet list structures and the sigs of the packets on
 *	the head of these structures. These packets must both be the same and
 *	the fully merged structure is returned in old and the minimal
 *	difference to get from old to new in new.
 */
int merge_packet_sigs(struct openpgp_signedpacket_list *old,
			struct openpgp_signedpacket_list *new)
{
	struct openpgp_packet_list	*lastpacket = NULL;
	struct openpgp_packet_list	*curpacket = NULL;
	struct openpgp_packet_list	*nextpacket = NULL;

	assert(compare_packets(old->packet, new->packet) == 0);

	curpacket = new->sigs;
	while (curpacket != NULL) {
		nextpacket = curpacket->next;
		/*
		 * TODO: We should be checking the signature and then
		 * potentially merging/replacing it depending on the subpackets
		 * really. For now this stops us adding the same one twice
		 * however.
		 */ 
		if (find_signature(old->sigs, curpacket->packet)) {
			/*
			 * We already have this sig, remove it from the
			 * difference list and free the memory allocated for
			 * it.
			 */
			if (lastpacket != NULL) {
				lastpacket->next = curpacket->next;
			} else {
				assert(curpacket == new->sigs);
				new->sigs = curpacket->next;
			}
			curpacket->next = NULL;
			free_packet_list(curpacket);
		} else {
			lastpacket = curpacket;
		}
		curpacket = nextpacket;
	}
	new->last_sig = lastpacket;

	/*
	 * What's left on new->sigs now are the new signatures, so add them to
	 * old->sigs.
	 */
	packet_list_add(&old->sigs, &old->last_sig, new->sigs);

	return 0;
}

/**
 *	merge_signed_packets - Takes 2 lists of signed packets and merges them.
 *	@old: The old signed packet list.
 *	@new: The new signed packet list.
 *
 *	Takes 2 lists of signed packets and merges them. The complete list of
 *	signed packets & sigs is returned in old and the minimal set of
 *	differences required to get from old to new in new.
 */
int merge_signed_packets(struct openpgp_signedpacket_list **old,
			struct openpgp_signedpacket_list **old_end,
			struct openpgp_signedpacket_list **new,
			struct openpgp_signedpacket_list **new_end)
{
	struct openpgp_signedpacket_list *curelem = NULL;
	struct openpgp_signedpacket_list *newelem = NULL;

	for (curelem = *old; curelem != NULL; curelem = curelem->next) {
		newelem = find_signed_packet(*new, curelem->packet);
		if (newelem != NULL) {
			merge_packet_sigs(curelem, newelem);
			
			/*
			 * If there are no sigs left on the new signed packet
			 * then remove it from the list.
			 */
			if (newelem->sigs == NULL) {
				remove_signed_packet(new,
						new_end,
						newelem->packet);
			}
		}
	}

	/*
	 * If *new != NULL now then there might be UIDs on the new key that
	 * weren't on the old key. Walk through them, checking if the UID is
	 * on the old key and if not adding them to it.
	 */
	for (curelem = *new; curelem != NULL;
			curelem = curelem->next) {

		if (find_signed_packet(*old, curelem->packet) == NULL) {
			ADD_PACKET_TO_LIST((*old_end),
				packet_dup(curelem->packet));
			if (*old == NULL) {
				*old = *old_end;
			}
			packet_list_add(&(*old_end)->sigs,
				&(*old_end)->last_sig,
				curelem->sigs);
		}
	}

	return 0;
}

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
int merge_keys(struct openpgp_publickey *a, struct openpgp_publickey *b)
{
	int rc = 0; /* Return code */
	struct openpgp_packet_list	*curpacket = NULL; 
	struct openpgp_packet_list	*lastpacket = NULL;
	struct openpgp_packet_list	*nextpacket = NULL;
	uint64_t keya, keyb;

	if (a == NULL || b == NULL) {
		/*
		 * Do nothing.
		 */
		return 1;
	}

	if (get_keyid(a, &keya) != ONAK_E_OK) {
		return 1;
	} else if (get_keyid(b, &keyb) != ONAK_E_OK) {
		return 1;
	} else if (keya != keyb) {
		/*
		 * Key IDs are different.
		 */
		rc = -1;
	} else {
		/*
		 * Key IDs are the same, so I guess we have to merge them.
		 */
		curpacket = b->sigs;
		while (curpacket != NULL) {
			nextpacket = curpacket->next;
			if (find_packet(a->sigs, curpacket->packet)) {
				/*
				 * We already have this signature, remove it
				 * from the difference list and free the memory
				 * allocated for it.
				 */

				if (lastpacket != NULL) {
					lastpacket->next = curpacket->next;
				} else {
					assert(curpacket == b->sigs);
					b->sigs = curpacket->next;
				}
				curpacket->next = NULL;
				free_packet_list(curpacket);

			} else {
				lastpacket = curpacket;
			}
			curpacket = nextpacket;
		}
		b->last_sig = lastpacket;

		/*
		 * Anything left on b->sigs doesn't exist on
		 * a->sigs, so add them to the list.
		 */
		packet_list_add(&a->sigs,
				&a->last_sig,
				b->sigs);

		/*
		 * Merge uids (signed list).
		 * Merge subkeys (signed list).
		 */
		merge_signed_packets(&a->uids, &a->last_uid, 
				&b->uids, &b->last_uid);
		merge_signed_packets(&a->subkeys, &a->last_subkey,
				&b->subkeys, &b->last_subkey);

	}

	/*
	 * If either key was revoked, make sure both the new ones are marked as
	 * being so.
	 */
	if (a->revoked || b->revoked) {
		a->revoked = b->revoked = true;
	}

	return rc;
}
