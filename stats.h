/*
 * stats.c - various routines to do stats on the key graph
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
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

#include <stdbool.h>
// #include <stdint.h>
#include <inttypes.h>

#include "ll.h"

/**
 *	struct stats_key - holds key details suitable for doing stats on.
 *	@keyid: The keyid.
 *	@colour: Used for marking during DFS/BFS.
 *	@parent: The key that lead us to this one for DFS/BFS.
 *	@sigs: A linked list of the signatures on this key.
 *	@gotsigs: A bool indicating if we've initialized the sigs element yet.
 */
struct stats_key {
	uint64_t keyid;
	int colour;
	uint64_t parent;
	struct ll *sigs;
	bool gotsigs;
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
unsigned long findpath(struct stats_key *have, struct stats_key *want);


struct stats_key *furthestkey(struct stats_key *have);

#endif /* __STATS_H__ */
