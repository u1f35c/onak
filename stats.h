/*
 * stats.c - various routines to do stats on the key graph
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 *
 * $Id: stats.h,v 1.5 2003/06/04 20:57:13 noodles Exp $
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

#include "keystructs.h"
#include "ll.h"

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
void dofindpath(uint64_t have, uint64_t want, bool html, int count);

struct stats_key *furthestkey(struct stats_key *have);

#endif /* __STATS_H__ */
