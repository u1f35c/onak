/*
	gpgstats.c - Program to produce stats on a GPG keyring.
	Written by Jonathan McDowell <noodles@earth.li>.

	19/02/2000 - Started writing (sort of).
*/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpgstats.h"
#include "hash.h"
#include "logging.h"
#include "ll.h"
#include "parse.h"

struct ll *finished = NULL;
struct ll *trees = NULL;

unsigned long hex2long(char *string)
{
	size_t loop;
	unsigned long value;

	value = 0;
	for (loop = 0; loop < 8 && loop < strlen(string) && string[loop] > ' ';
			loop++) {
		value=((string[loop]>'9') ? toupper(string[loop])-'A'+10 :
					string[loop]-'0')+(value << 4);
	}
	return value;
}


int keycmp(struct key *key1, struct key *key2)
{
	if (key1->keyid==key2->keyid) {
		return 0;
	}
	return 1;
}


struct ll *addkey(struct ll *curkey, struct key newkey)
{
	return lladd(curkey, copyandaddtohash(newkey));
}


void initcolour(int pi) {
	unsigned long loop;
	struct ll *curkey;

	/* Init the colour/pi hashes */
	for (loop=0; loop<HASHSIZE; loop++) {
		curkey = gethashtableentry(loop);
		while (curkey!=NULL) {
			((struct key *)curkey->object)->colour = 0;
			if (pi != NULL) {
				((struct key *)curkey->object)->pi = NULL;
			}
			curkey = curkey->next;
		}
	}
}


void readkeys(const char *filename)
{
	char curline[1024];
	unsigned long keys=0,sigs=0,pub=0, revoked=0;
	struct key keyin;
	struct key *curkey=NULL, *cursign=NULL;
	struct key cursig;
	FILE *keyfile;
	int (*p)();

	p=keycmp;
	keyin.name=cursig.name=NULL;
	keyin.sigs=keyin.signs=cursig.sigs=cursig.signs=NULL;
	keyin.selfsigned=cursig.selfsigned=0;
	keyin.revoked=cursig.revoked=0;

	log(LOG_INFO, "Reading key info from '%s'.\n", filename);
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
			keyin.keyid=hex2long(&curline[1]);
			curkey=copyandaddtohash(keyin);
			if (curkey->keyid!=keyin.keyid) {
				printf("Erk! Didn't get back the key we asked for! %08lX != %08lX\n", curkey->keyid, keyin.keyid);
			}
		} else if (curline[0]=='S') {
			cursig.keyid=hex2long(&curline[1]);
			if (curkey->keyid==cursig.keyid) {
				curkey->selfsigned=1;
			}

			if (!llfind(curkey->sigs, &cursig, p)) {
				curkey->sigs=addkey(curkey->sigs, cursig);
				++sigs;
			}

			if ((cursign=findinhash(&cursig))==NULL) {
				cursign=copyandaddtohash(cursig);
			}
			if (cursign->keyid!=cursig.keyid) {
				printf("Erk! Didn't get back the key we asked for! %08lX != %08lX\n", cursign->keyid, cursig.keyid);
			}

			if (!llfind(cursign->signs, curkey, p))
				cursign->signs=addkey(cursign->signs, *curkey);
		} else if (curline[0]=='N') {
			if (curkey->name==NULL) {
				curkey->name=strdup(&curline[1]);
				curkey->name[strlen(curkey->name)-1]=0;
				if (strcmp(curkey->name, "[revoked]")==0) {
					curkey->revoked=1;
					++revoked;
				}
			}
		}
		fgets(curline, 1023, keyfile);
	}
	fclose(keyfile);
	printf("\rRead %lu keys, %lu pub, %lu sigs, %lu revoked.\n",
		keys, pub, sigs, revoked);
}


void DFSVisit(int type, struct key *key, unsigned long *time, unsigned long *depth)
{
	struct ll *curkey;
	struct key *v;

	key->colour=1;
//	key->d=(*time)++;

	if (type==0) curkey=key->signs; else curkey=key->sigs;
	while (curkey!=NULL) {
		v=(struct key *)findinhash(curkey->object);
		if (v==NULL) {
			printf("Couldn't find key in hash. Most odd.\n");
		}
		if (v!=NULL && v->colour==0) {
			if (type==1 && key->pi==NULL) {
				printf("key->pi is NULL.\n");
			} else if (type==1) {
				key->pi->object=lladd(key->pi->object, v);
				v->pi=key->pi;
			}

			(*depth)++;
			DFSVisit(type, v, time, depth);
		}
		curkey=curkey->next;
	}
	key->colour=2;
//	key->f=(*time)++;
	if (type==0) finished=lladd(finished, key);
}


void DFS(void)
{
	unsigned long loop,time=0,depth,maxdepth=0;
	struct ll *curkey;

	initcolour(1);
	for (loop=0; loop<HASHSIZE; loop++) {
		curkey=gethashtableentry(loop);
		while (curkey!=NULL) {
			if (((struct key *)curkey->object)->colour==0) {
				depth=0;
				DFSVisit(0, ((struct key *)curkey->object),
					&time, &depth);
				if (depth>maxdepth) maxdepth=depth;
			}
			curkey=curkey->next;
		}
	}
	printf("Max depth reached in DFS(): %ld\n", maxdepth);
}


void DFSsorted(void)
{
	unsigned long time=0,depth,maxdepth=0;
	struct ll *curkey;

	initcolour(1);
	curkey=finished;
	while (curkey!=NULL) {
		if (((struct key *)curkey->object)->colour==0) {
			trees=lladd(trees, curkey->object);
			((struct key *)curkey->object)->pi=trees;
			((struct key *)curkey->object)->pi->object=lladd(NULL, curkey->object);

			depth=0;
			DFSVisit(1, ((struct key *)curkey->object),
				&time, &depth);
			if (depth>maxdepth) maxdepth=depth;
		}
		curkey=curkey->next;
	}
	printf("Max depth reached in DFSsorted(): %ld\n", maxdepth);
}


long checkselfsig()
{
	unsigned long loop;
	struct ll *curkey;
	unsigned long selfsig=0;

	for (loop=0; loop<HASHSIZE; loop++) {
		curkey=gethashtableentry(loop);
		while (curkey!=NULL) {
			if (((struct key *)curkey->object)->selfsigned) ++selfsig;
			curkey=curkey->next;
		}
	}

	return selfsig;
}


void printtrees(int minsize)
{
	struct ll *curtree,*curkey;
	unsigned long count, total;

	curtree=trees;
	total=0;
	while (curtree!=NULL) {	
		curkey=curtree->object;
		++total;
		count=0;
		if (llsize(curkey)>=minsize) while (curkey!=NULL) {
			printf("0x%08lX (%s)\n", ((struct key *)curkey->object)->keyid,
				((struct key *)curkey->object)->name);
			count++;
			curkey=curkey->next;
		}
		if (count>=minsize) printf("Tree size of %ld\n", count);
		curtree=curtree->next;
	}
	printf("Total of %ld trees.\n", total);
}


unsigned long size2degree(struct ll *curll, struct key *prev, int sigs, int curdegree, int maxdegree, int *rec)
{
	unsigned long count=0;
	struct ll *nextll;

	++curdegree;
	++(*rec);

	nextll=NULL;
	while (curll!=NULL) {
		if (((struct key *) curll->object)->revoked==1) {
			/* It's revoked. Ignore it. */
		} else if (((struct key *) curll->object)->colour==0) {
			/* We've never seen it. Count it, mark it and
				explore its subtree */
			count++;
			printf("0x%08lX (%s)\n", ((struct key *) curll->object)->keyid,
				((struct key *) curll->object)->name);
			((struct key *)curll->object)->colour=curdegree;
			((struct key *)curll->object)->pi=(struct ll *) prev;
			nextll=lladd(nextll, curll->object);
		} else if (((struct key *) curll->object)->colour>curdegree) {
			/* We've seen it, but it it's closer to us than we
				thought. Re-evaluate, but don't count it
				again */
			((struct key *)curll->object)->colour=curdegree;
			((struct key *)curll->object)->pi=(struct ll *) prev;
			nextll=lladd(nextll, curll->object);
		}
		curll=curll->next;
	}
	/* Now we've marked, let's recurse */
	if (curdegree<maxdegree) curll=nextll; else curll=NULL;
	while (curll!=NULL) {
		if (sigs) {
			count += size2degree(((struct key *)curll->object)->sigs, curll->object, sigs, curdegree, maxdegree, rec);
		} else {
			count += size2degree(((struct key *)curll->object)->signs, curll->object, sigs, curdegree, maxdegree, rec);
		}
		nextll=curll->next;
		free(curll);
		curll=nextll;
	}

	return count;
}


void sixdegrees(unsigned long keyid)
{
	struct key *keyinfo, key;
	int loop;
	int rec;

	key.keyid=keyid;

	if ((keyinfo=findinhash(&key))==NULL) {
		printf("Couldn't find key 0x%08lX.\n", keyid);
		return;
	}

	printf("Six degrees for 0x%08lX (%s):\n", keyinfo->keyid, keyinfo->name);

	puts("\t\t   Signs       Signed by");
	for (loop=1; loop<7; loop++) {
		initcolour(0);
		rec=0;
		printf("Degree %d:\t%8ld", loop, size2degree(keyinfo->signs, NULL, 0, 0, loop, &rec));
		printf(" (%d)", rec);
		initcolour(0);
		rec=0;
		printf("\t%8ld", size2degree(keyinfo->sigs, NULL, 1, 0, loop, &rec));
		printf(" (%d)\n", rec);
	}
}


void showkeysigs(unsigned long keyid, int sigs)
{
	struct key *keyinfo, key;
	struct ll *cursig;

	key.keyid=keyid;

	if ((keyinfo=findinhash(&key))==NULL) {
		printf("Couldn't find key 0x%08lX.\n", keyid);
		return;
	}

	printf("0x%08lX (%s) %s:\n", keyinfo->keyid, keyinfo->name,
			sigs ? "is signed by" : "signs");

	if (sigs) cursig=keyinfo->sigs; else cursig=keyinfo->signs;
	while (cursig!=NULL) {
		printf("\t0x%08lX (%s)\n", ((struct key *)cursig->object)->keyid,
				((struct key *)cursig->object)->name);
		cursig=cursig->next;
	}
}


void findpath(unsigned long keyida, unsigned long keyidb)
{
	struct key *keyinfoa, *keyinfob, *curkey, keya, keyb;
	int rec;

	keya.keyid=keyida;
	keyb.keyid=keyidb;

	if ((keyinfoa=findinhash(&keya))==NULL) {
		printf("Couldn't find key 0x%08lX.\n", keyida);
		return;
	}
	if ((keyinfob=findinhash(&keyb))==NULL) {
		printf("Couldn't find key 0x%08lX.\n", keyidb);
		return;
	}

	/* Fill the tree info up */
	initcolour(1);
	rec=0;
	size2degree(keyinfoa->signs, keyinfoa, 0, 0, 1000, &rec);
	keyinfoa->pi=NULL;

	printf("%d recursions required.\n", rec);
	if (keyinfob->colour==0) {
		printf("Can't find a link from 0x%08lX to 0x%08lX\n", keyida, keyidb);
	} else {
		printf("%d steps from 0x%08lX to 0x%08lX\n", keyinfob->colour, keyida, keyidb);
		curkey=keyinfob;
		while (curkey!=NULL) {
			printf("0x%08lX (%s)\n", curkey->keyid, curkey->name);
			curkey=(struct key *)curkey->pi;
		}
	}
}


int main(int argc, char *argv[])
{
	struct key *keyinfo,foo;
	int rec;

	printf("gpgstats %s by Jonathan McDowell\n", VERSION);
	puts("Copyright 2000 Project Purple. Released under the GPL.");
	puts("A simple program to do stats on a GPG keyring.\n");
	inithash();
//	readkeys("keyfile");
	readkeys("keyfile.debian");
//	readkeys("../keyfile.big");
	printf("%ld selfsigned.\n", checkselfsig());
	printf("%ld distinct keys.\n", hashelements());

	finished=trees=NULL;
	printf("Starting first DFS.\n");
	DFS();
	printf("Starting second DFS.\n");
	DFSsorted();
	printtrees(2);

//	foo.keyid=0xC7A966DD; /* Phil Zimmerman himself */
//	if ((keyinfo=findinhash(&foo))==NULL) {
//		printf("Couldn't find key 0x%08lX.\n", foo.keyid);
//		return 1;
//	}

//	initcolour(0);
//	rec=0;
//	printf("%ld\n", size2degree(keyinfo->sigs, NULL, 0, 0, 1000, &rec));
//	return 0;
}
