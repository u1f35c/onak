/*
 * merge.c - Routines to merge OpenPGP public keys.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "decodekey.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "ll.h"
#include "log.h"
#include "mem.h"
#include "merge.h"

/**
 *	compare_packets - Check to see if 2 OpenPGP packets are the same.
 *	@a: The first packet to compare.
 *	@b: The second packet to compare.
 *
 *	Takes 2 packets and returns true if they are the same and false
 *	otherwise.
 */
bool compare_packets(struct openpgp_packet *a, struct openpgp_packet *b)
{
	return (a->tag == b->tag && a->length == b->length &&
		!memcmp(a->data, b->data, b->length));
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
	return (sig_keyid(a) == sig_keyid(b));
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
		if (compare_packets(packet_list->packet, packet)) {
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
		if (compare_packets(packet_list->packet, packet)) {
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
bool remove_signed_packet(struct openpgp_signedpacket_list **packet_list,
		struct openpgp_signedpacket_list **list_end,
		struct openpgp_packet *packet)
{
	struct openpgp_signedpacket_list *cur = NULL;
	struct openpgp_signedpacket_list *prev = NULL;
	bool found = false;

	for (cur = *packet_list; !found && (cur != NULL); cur = cur->next) {
		if (compare_packets(cur->packet, packet)) {
			found = true;
			if (prev == NULL) {
				*packet_list = cur->next;
			} else {
				prev->next = cur->next;
			}
			if (cur->next == NULL) {
				*list_end = prev;
			}
			// TODO: Free the removed signed packet...
		}
		prev = cur;
	}

	return found;
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

	assert(compare_packets(old->packet, new->packet));

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

	if (a == NULL || b == NULL) {
		/*
		 * Do nothing.
		 */
		rc = 1;
	} else if (get_keyid(a) != get_keyid(b)) {
		/*
		 * Key IDs are different.
		 */
		rc = -1;
	} else {
		/*
		 * Key IDs are the same, so I guess we have to merge them.
		 */
		curpacket = b->revocations;
		while (curpacket != NULL) {
			nextpacket = curpacket->next;
			if (find_packet(a->revocations, curpacket->packet)) {
				/*
				 * We already have this revocation, remove it
				 * from the difference list and free the memory
				 * allocated for it.
				 */

				if (lastpacket != NULL) {
					lastpacket->next = curpacket->next;
				} else {
					assert(curpacket == b->revocations);
					b->revocations = curpacket->next;
				}
				curpacket->next = NULL;
				free_packet_list(curpacket);

			} else {
				lastpacket = curpacket;
			}
			curpacket = nextpacket;
		}
		b->last_revocation = lastpacket;

		/*
		 * Anything left on b->revocations doesn't exist on
		 * a->revocations, so add them to the list.
		 */
		packet_list_add(&a->revocations,
				&a->last_revocation,
				b->revocations);

		/*
		 * Merge uids (signed list).
		 * Merge subkeys (signed list).
		 */
		merge_signed_packets(&a->uids, &a->last_uid, 
				&b->uids, &b->last_uid);
		merge_signed_packets(&a->subkeys, &a->last_subkey,
				&b->subkeys, &b->last_subkey);

	}

	return rc;
}

/**
 *	update_keys - Takes a list of public keys and updates them in the DB.
 *	@keys: The keys to update in the DB.
 *
 *	Takes a list of keys and adds them to the database, merging them with
 *	the key in the database if it's already present there. The key list is
 *	update to contain the minimum set of updates required to get from what
 *	we had before to what we have now (ie the set of data that was added to
 *	the DB). Returns the number of entirely new keys added.
 */
int update_keys(struct openpgp_publickey **keys)
{
	struct openpgp_publickey *curkey = NULL;
	struct openpgp_publickey *oldkey = NULL;
	struct openpgp_publickey *prev = NULL;
	int newkeys = 0;
	bool intrans;

	for (curkey = *keys; curkey != NULL; curkey = curkey->next) {
		intrans = starttrans();
		logthing(LOGTHING_INFO,
			"Fetching key 0x%llX, result: %d",
			get_keyid(curkey),
			fetch_key(get_keyid(curkey), &oldkey, intrans));

		/*
		 * If we already have the key stored in the DB then merge it
		 * with the new one that's been supplied. Otherwise the key
		 * we've just got is the one that goes in the DB and also the
		 * one that we send out.
		 */
		if (oldkey != NULL) {
			merge_keys(oldkey, curkey);
			if (curkey->revocations == NULL &&
					curkey->uids == NULL &&
					curkey->subkeys == NULL) {
				if (prev == NULL) {
					*keys = curkey->next;
				} else {
					prev->next = curkey->next;
					curkey->next = NULL;
					free_publickey(curkey);
					curkey = prev;
				}
			} else {
				prev = curkey;
				logthing(LOGTHING_INFO,
					"Merged key; storing updated key.");
				store_key(oldkey, intrans, true);
			}
			free_publickey(oldkey);
			oldkey = NULL;
		} else {
			logthing(LOGTHING_INFO,
				"Storing completely new key.");
			store_key(curkey, intrans, false);
			newkeys++;
		}
		endtrans();
		intrans = false;
	}

	return newkeys;
}
