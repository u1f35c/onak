/*
	grahpstuff.c - Code to handle the various graph algorithms
	Written by Jonathan McDowell <noodles@earth.li>.

	19/02/2000 - Started writing (sort of).
*/

// #include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#include "gpgstats.h"
#include "hash.h"
/* #include "ll.h"
#include "parse.h" */
#include "graphstuff.h"

struct keycount { unsigned long count; struct stats_key *k; };

struct ll *finished=NULL;
struct ll *trees=NULL;


int keycmp(struct stats_key *key1, struct stats_key *key2)
{
	if (key1->keyid == key2->keyid) {
		return 0;
	}
	return 1;
}


struct ll *addkey(struct ll *curkey, uint64_t keyid)
{
	return lladd(curkey, createandaddtohash(keyid));
}

void readkeys(const char *filename)
{
	char curline[1024];
	unsigned long keys=0,sigs=0,pub=0, revoked=0;
	uint64_t keyin = 0;
	uint64_t cursig = 0;
	struct stats_key *curkey=NULL, *cursign=NULL;
	FILE *keyfile;
	int (*p)();

	p=keycmp;

	printf("Reading key info from '%s'.\n", filename);
	if ((keyfile=fopen(filename, "r"))==NULL) {
		perror("readkeys()");
		return;
	}
	/* read a line */
	fgets(curline, 1023, keyfile);
	while (!feof(keyfile)) {	
		if (curline[0]=='P') {
			++pub;
			++keys;
			printf("\rRead %ld keys so far.", keys);
			keyin = strtoul(&curline[1], NULL, 16);
			curkey = createandaddtohash(keyin);
		} else if (curline[0]=='S') {
			cursig = strtoul(&curline[1], NULL, 16);
/*			if (curkey->keyid==cursig) {
				curkey->selfsigned=1;
			} */

			if (!llfind(curkey->sigs, &cursig, p)) {
				curkey->sigs = addkey(curkey->sigs, cursig);
				++sigs;
			}

			if ((cursign=findinhash(cursig))==NULL) {
				cursign = createandaddtohash(cursig);
			}

//SIGNS			if (!llfind(cursign->signs, curkey, p)) {
//SIGNS				cursign->signs = addkey(cursign->signs,
//SIGNS						curkey->keyid);
//SIGNS			}
		} else if (curline[0]=='N') {
/*			if (curkey->name==NULL) {
				curkey->name=strdup(&curline[1]);
				curkey->name[strlen(curkey->name)-1]=0;
				if (strcmp(curkey->name, "[revoked]")==0) {
					curkey->revoked=1;
					++revoked;
				}
			} */
		}
		fgets(curline, 1023, keyfile);
	}
	fclose(keyfile);
	printf("\rRead %ld keys, %ld pub, %ld sigs, %ld revoked.\n", keys, pub, sigs, revoked);
	printf("\rRead %ld keys, %ld pub, %ld sigs, %ld revoked.\n", keys, pub, sigs, revoked);
}


void DFSVisit(int type, struct stats_key *key, unsigned long *time, unsigned long *depth)
{
	struct ll *curkey;
	struct stats_key *v;

	key->colour=1;
//	key->d=(*time)++;

	if (type == 0) {
//SIGNS		curkey = key->signs;
	} else {
		curkey = key->sigs;
	}
	while (curkey != NULL) {
		v = (struct stats_key *)findinhash(
				((struct stats_key *) curkey->object)->keyid);
		if (v == NULL) {
			printf("Couldn't find key in hash. Most odd.\n");
		}
		if (v != NULL && v->colour == 0) {
			if (type == 1 && key->parent == 0) {
				printf("key->parent is 0.\n");
			} else if (type == 1) {
				key->parent->object = lladd(key->parent->object,
						v);
				v->parent = key->parent;
			}

			(*depth)++;
			DFSVisit(type, v, time, depth);
		}
		curkey=curkey->next;
	}
	key->colour = 2;
//	key->f=(*time)++;
	if (type == 0) {
		finished=lladd(finished, key);
	}
}


unsigned long DFS(void)
{
	unsigned long loop,time=0,depth,maxdepth=0;
	struct ll *curkey;

	initcolour(1);
	for (loop=0; loop<HASHSIZE; loop++) {
		curkey=gethashtableentry(loop);
		while (curkey!=NULL) {
			if (((struct stats_key *)curkey->object)->colour==0) {
				depth=0;
				DFSVisit(0, ((struct stats_key *)curkey->object),
					&time, &depth);
				if (depth>maxdepth) maxdepth=depth;
			}
			curkey=curkey->next;
		}
	}
	return maxdepth;
}


unsigned long DFSsorted(void)
{
	unsigned long time=0,depth,maxdepth=0;
	struct ll *curkey;

	initcolour(1);
	curkey=finished;
	while (curkey != NULL) {
		if (((struct stats_key *)curkey->object)->colour == 0) {
			trees = lladd(trees, curkey->object);
			((struct stats_key *)curkey->object)->parent =
				trees;
			((struct stats_key *)curkey->object)->parent->object =
				lladd(NULL, curkey->object);

			depth = 0;
			DFSVisit(1, ((struct stats_key *)curkey->object),
				&time, &depth);
			if (depth>maxdepth) {
				maxdepth = depth;
			}
		}
		curkey = curkey->next;
	}
	return maxdepth;
}

long checkselfsig()
{
	unsigned long loop;
	struct ll *curkey;
	unsigned long selfsig=0;

	for (loop = 0; loop < HASHSIZE; loop++) {
		curkey = gethashtableentry(loop);
		while (curkey != NULL) {
//SELFSIGNED		if (((struct stats_key *)curkey->object)->selfsigned) {
//SELFSIGNED			++selfsig;
//SELFSIGNED		}
			curkey = curkey->next;
		}
	}

	return selfsig;
}


unsigned long countdegree(struct stats_key *have, int sigs, int maxdegree)
{
	unsigned long count = 0, curdegree = 0;
	struct ll *curll, *nextll, *sigll, *tmp;

	++curdegree;

	nextll = NULL;
	curll = lladd(NULL, have);

	while (curll != NULL && curdegree <= maxdegree) {
		if (sigs) {
			sigll = ((struct stats_key *)curll->object)->sigs;
		} else {
//SIGNS			sigll = ((struct stats_key *)curll->object)->signs;
		}
		while (sigll!=NULL) {
			if (((struct stats_key *) sigll->object)->colour==0) {
				/* We've never seen it. Count it, mark it and
					explore its subtree */
				count++;
				((struct stats_key *)sigll->object)->colour=curdegree;
				((struct stats_key *)sigll->object)->parent = 
					((struct stats_key *)
					 curll->object)->keyid;
				nextll=lladd(nextll, sigll->object);
			}
			sigll = sigll->next;
		}
		tmp = curll->next;
		free(curll);
		curll = tmp;
		if (curll == NULL) {
			curll = nextll;
			nextll = NULL;
			++curdegree;
		};
	}

	return count;
}

