//#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "hash.h"
#include "keydb.h"
#include "stats.h"

void dofindpath(uint64_t have, uint64_t want, bool html)
{
	struct stats_key *keyinfoa, *keyinfob, *curkey;
	int rec;

	/*
	 * Make sure the key we have and want are in the cache.
	 */
	hash_getkeysigs(have);
	hash_getkeysigs(want);

	if ((keyinfoa = findinhash(have)) == NULL) {
		printf("550 Couldn't find key 0x%llX.\n", have);
		return;
	}
	if ((keyinfob = findinhash(want)) == NULL) {
		printf("550 Couldn't find key 0x%llX.\n", want);
		return;
	}
	
	/*
	 * Fill the tree info up.
	 */
	initcolour(true);
	rec = findpath(keyinfoa, keyinfob);
	keyinfob->parent = 0;

	printf("%d nodes examined. %ld elements in the hash\n", rec,
			hashelements());
	if (keyinfoa->colour == 0) {
		printf("550 Can't find a link from 0x%llX to 0x%llX\n",
				have,
				want);
	} else {
		printf("250-%d steps from 0x%llX to 0x%llX\n",
				keyinfoa->colour, have, want);
		curkey = keyinfoa;
		while (curkey != NULL) {
			printf("250-0x%llX (%s)\n",
					curkey->keyid,
					keyid2uid(curkey->keyid));
			curkey = findinhash(curkey->parent);
		}
	}
}

int main(int argc, char *argv[])
{
	initdb();
	inithash();
	dofindpath(0x5B430367, 0x3E1D0C1C, false);
	dofindpath(0x3E1D0C1C, 0x5B430367, false);
	cleanupdb();

	return EXIT_SUCCESS;
}
