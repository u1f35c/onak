/*
	gpgstats.c - Program to produce stats on a GPG keyring.
	Written by Jonathan McDowell <noodles@earth.li>.

	19/02/2000 - Started writing (sort of).
*/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef USEREADLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "gpgstats.h"
#include "graphstuff.h"
#include "hash.h"
#include "keydb.h"
#include "ll.h"
#include "parse.h"
#include "stats.h"

struct keycount { unsigned long count; struct key *k; };

extern struct ll *trees;
extern struct ll *finished;

void insertval(unsigned long val, struct keycount a[], struct key *curkey)
{
	int loop;

	loop=9;
	if (val<a[loop--].count) return;

	while (val>a[loop].count && loop >= 0) {
		a[loop+1]=a[loop];
		loop--;
	}
	a[loop+1].count=val;
	a[loop+1].k=curkey;
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
		while (curkey!=NULL) {
			count++;
			curkey=curkey->next;
		}
		if (count>=minsize) {
//			log(LOG_INFO, "Tree size of %ld\n", count);
		}
		curtree=curtree->next;
	}
//	log(LOG_INFO, "Total of %ld trees.\n", total);
}

void showkeysigs(uint64_t keyid, bool sigs)
{
	struct stats_key *keyinfo = NULL;
	struct ll *cursig;
	long count;

	if ((keyinfo = findinhash(keyid)) == NULL) {
		printf("Couldn't find key 0x%llX.\n", keyid);
		return;
	}

	printf("0x%llX (%s) %s:\n", keyinfo->keyid, keyid2uid(keyinfo->keyid),
			sigs ? "is signed by" : "signs");

	if (sigs) {
		cursig = keyinfo->sigs;
	} else {
//		cursig = keyinfo->signs;
	}
	count=0;
	while (cursig!=NULL) {
		count++;
		printf("\t0x%08lX (%s)\n",
				((struct key *)cursig->object)->keyid,
			keyid2uid(((struct key *)cursig->object)->keyid));
		cursig=cursig->next;
	}

	printf("\t%s a total of %ld keys.\n", sigs ? "Signed by" : "Signs",
						count); 
}

void memstats()
{
	unsigned long loop, total, hash, hashmax, hashmin, cur, sigs, signs;
	unsigned long names;
	struct ll *curkey;

	total=sigs=signs=hash=names=0;
	hashmin=-1;
	hashmax=0;

	for (loop=0; loop<HASHSIZE; loop++) {
		curkey=gethashtableentry(loop);
		cur=llsize(curkey);
		if (cur>hashmax) hashmax=cur;
		if (cur<hashmin) hashmin=cur;
		hash+=cur;
		while (curkey!=NULL) {
			sigs+=llsize(((struct key *)curkey->object)->sigs);
			signs+=llsize(((struct key *)curkey->object)->signs);
			if (((struct key *)curkey->object)->name!=NULL)
			names+=strlen(((struct key *)curkey->object)->name);
			curkey=curkey->next;
		}
	}

	printf("%10ld bytes in %ld keys\n", hash*sizeof(struct key), hash);
	total += hash*sizeof(struct key);
	printf("%10ld bytes in hash structure\n", hash*sizeof(struct ll));
	total += hash*sizeof(struct ll);
	printf("           (Max hash bucket %ld, min hash bucket %ld.)\n", hashmax, hashmin);
	printf("%10ld bytes in %ld sigs.\n", sigs*sizeof(struct ll), sigs);
	total += sigs*sizeof(struct ll);
	printf("%10ld bytes in %ld signs.\n", signs*sizeof(struct ll), signs);
	total += signs*sizeof(struct ll);
	printf("%10ld bytes in names.\n", names);
	total += names;
	printf("%10ld bytes total.\n", total);
}

void showmostsigns(int sigs)
{
	unsigned long count,loop;
	struct keycount signs[10];
	struct ll *curkey;

	memset(signs, 0, sizeof(signs));
	// for (count=0; count<10; count++) { signs[count].count=0; };
	count=0;
	for (loop=0; loop<HASHSIZE; loop++) {
		curkey=gethashtableentry(loop);
		while (curkey!=NULL) {
			if (sigs) {
				count=llsize(((struct key *)curkey->object)->sigs);
			} else {
				count=llsize(((struct key *)curkey->object)->signs);
			}
			if (count != 0) {
				insertval(count, signs, (struct key *)curkey->object);
			}
			curkey=curkey->next;
		}
	}
	
	for (count=0; count<10; count++) {
		if (signs[count].k != NULL) {
			printf("0x%08lX (%s) %s %ld keys.\n",
				signs[count].k->keyid, signs[count].k->name,
				sigs ? "is signed by" : "signs",
				signs[count].count);
		}
	}
}

void showhelp(void)
{
	printf("gpgstats %s by Jonathan McDowell\n", VERSION);
	puts("A simple program to do stats on a GPG keyring.\n");

	puts("DFS <minsize>\t\tOutput details on the strongly connected");
	puts("\t\t\tsubtrees, min size <minsize>");
	puts("MAXPATH\t\t\tShow the two further apart keys.");
	puts("MEMSTATS\t\tShow some stats about memory usage.");
	puts("MOSTSIGNED\t\tShow the 10 keys signed by most others.");
	puts("PATH <keyida> <keyidb>\tShows the path of trust (if any) from.");
	puts("\t\t\tkeyida to keyidb (ie I have keyida, I want keyidb).");
	puts("QUIT\t\t\tQuits the program.");
	puts("READ <file>\t\tRead <file> in and add to the loaded keyring.");
	puts("SIGNS <keyid>\t\tShows the keys that the given key signs.");
	puts("SIGNSMOST\t\tShow the 10 keys that sign most other keys.");
	puts("SIGS <keyid>\t\tShows the signatures on the given key.");
	puts("SIXDEGREES <keyid>\tShows the 6 degrees from the given keyid.");
	puts("STATS\t\t\tDisplay some stats about the loaded keyring.");
}

void commandloop(void)
{
	struct cfginf commands[]={{"QUIT", 0,  NULL},
				{"READ", 1, NULL},
				{"SIXDEGREES", 1, NULL},
				{"PATH", 1, NULL},
				{"SIGS", 1, NULL},
				{"SIGNS", 1, NULL},
				{"STATS", 0, NULL},
				{"HELP", 0, NULL},
				{"DFS", 1, NULL},
				{"SIGNSMOST", 0, NULL},
				{"MOSTSIGNED", 0, NULL},
				{"MEMSTATS", 0, NULL},
				{"MAXPATH", 1, NULL}};
	char tmpstr[1024];
	char *param;
	int cmd;

	commands[1].var=commands[2].var=commands[3].var=&param;
	commands[4].var=commands[5].var=commands[8].var=&param;
	commands[12].var=&param;

	do {
		memset(tmpstr, 0, 1023);
		fgets(tmpstr, 1023, stdin);
//		printf("Read: '%s'\n", tmpstr);
		cmd=parseline(commands, tmpstr);
//		printf("Got command: '%d'\n", cmd);
//		printf("Got command: '%d'\n", cmd);

		switch (cmd) {
		case 2:
			readkeys(param);
			break;
		case 4:
			//dofindpath(strtoul(param, NULL, 16),
			//	strtoul(strchr(param, ' ')+1, NULL, 16));
			break;
		case 5:
			showkeysigs(strtoul(param, NULL, 16), true);
			break;
		case 6:
			showkeysigs(strtoul(param, NULL, 16), false);
			break;
		case 7:
			printf("%ld keys currently loaded, %ld self signed.\n",
					hashelements(),
					checkselfsig());
			break;
		case 8:
			showhelp();
			break;
		case 9:
			finished=trees=NULL;
			printf("Starting first DFS.\n");
			DFS();
			printf("Starting second DFS.\n");
			DFSsorted();
			printtrees(atoi(param));
			break;
		case 10:
			showmostsigns(0);
			break;
		case 11:
			showmostsigns(1);
			break;
		case 12:
			memstats();
			break;
		}
	} while (cmd!=1);
}


int main(int argc, char *argv[])
{
	printf("gpgstats %s by Jonathan McDowell\n", VERSION);
	puts("Copyright 2000 Project Purple. Released under the GPL.");
	puts("A simple program to do stats on a GPG keyring.\n");

	inithash();
	readkeys("keyfile");
	printf("%ld selfsigned.\n", checkselfsig());
	printf("%ld distinct keys.\n", hashelements());

	commandloop();
	return 0;
}
