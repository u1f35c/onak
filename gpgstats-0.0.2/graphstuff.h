/*
	grahpstuff.h - Code to handle the various graph algorithms
	Written by Jonathan McDowell <noodles@earth.li>.

	19/02/2000 - Started writing (sort of).
*/

#ifndef __GRAPHSTUFF_H__
#define __GRAPHSTUFF_H__

#include <stdint.h>

#include "stats.h"

int keycmp(struct stats_key *key1, struct stats_key *key2);
struct ll *addkey(struct ll *curkey, uint64_t keyid);
void readkeys(const char *filename);
void DFSVisit(int type, struct stats_key *key,
		unsigned long *time, unsigned long *depth);
unsigned long DFS(void);
unsigned long DFSsorted(void);
long checkselfsig();
unsigned long countdegree(struct stats_key *have, int sigs, int maxdegree);

#endif /*__GRAPHSTUFF_H__ */
