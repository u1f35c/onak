/*
 * stats.c - various routines to do stats on the key graph
 *
 * Copyright 2000-2004,2007-2009 Jonathan McDowell <noodles@earth.li>
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

/* MOSTSIGNED
SIGNSMOST
SIGNS <key>
SIGS <key>
SIXDEGREES <keyid>
MAXPATH

key_getsigs - get the sigs for a key.
key_getsigns - get the keys a key signs. */

#ifndef __STATS_H__
#define __STATS_H__

#include <inttypes.h>
#include <stdbool.h>

#include "keydb.h"
#include "ll.h"

/**
 * @brief Holds key details suitable for doing stats on.
 */
struct stats_key {
	/** The keyid. */
	uint64_t keyid;
	/** Used for marking during DFS/BFS. */
	int colour;
	/** The key that lead us to this one for DFS/BFS. */
	uint64_t parent;
	/** A linked list of the signatures on this key. */
	struct ll *sigs;
	/** A linked list of the keys this key signs. */
	struct ll *signs;
	/** A bool indicating if we've initialized the sigs element yet. */
	bool gotsigs;
	/** If we shouldn't consider the key in calculations. */
	bool disabled;
	/** If the key is revoked (and shouldn't be considered). */
	bool revoked;
};

/**
 *	initcolour - Clear the key graph ready for use.
 *	@parent: Do we want to clear the parent pointers too?
 *
 *	Clears the parent and colour information on all elements in the key
 *	graph.
 */
void initcolour(bool parent);

/**
 *	findpath - Given 2 keys finds a path between them.
 *	@have: The key we have.
 *	@want: The key we want to get to.
 *
 *	This does a breadth first search on the key tree, starting with the
 *	key we have. It returns as soon as a path is found or when we run out
 *	of keys; whichever comes sooner.
 */
unsigned long findpath(struct onak_dbctx *dbctx,
		struct stats_key *have, struct stats_key *want);

/**
 *	dofindpath - Given 2 keys displays a path between them.
 *	@have: The key we have.
 *	@want: The key we want to get to.
 *	@html: Should we output in html.
 *	@count: How many paths we should look for at most.
 *
 *	This does a breadth first search on the key tree, starting with the
 *	key we have. It returns as soon as a path is found or when we run out
 *	of keys; whichever comes sooner.
 */
void dofindpath(struct onak_dbctx *dbctx,
		uint64_t have, uint64_t want, bool html, int count);

struct stats_key *furthestkey(struct onak_dbctx *dbctx, struct stats_key *have);

#endif /* __STATS_H__ */
