/*
 * wotsap.c - Output a set of wotsap files from an onak keyring
 *
 * See:
 *
 * http://www.lysator.liu.se/~jc/wotsap/wotfileformat.txt
 *
 * for more details of the format.
 *
 * Copyright 2013 Jonathan McDowell <noodles@earth.li>
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

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "build-config.h"

#include "hash.h"
#include "log.h"
#include "onak-conf.h"
#include "stats.h"

static struct ll *sortkeyll(struct ll *keys)
{
	struct ll *newll, *tmp, **curobj;
	struct stats_key *curkey, *toadd;

	newll = NULL;
	while (keys) {
		toadd = (struct stats_key *) keys->object;
		curobj = &newll;
		while (*curobj) {
			curkey = (struct stats_key *) (*curobj)->object;
			if (curkey->keyid >= toadd->keyid) {
				break;
			}
			curobj = &((*curobj)->next);
		}

		tmp = keys->next;
		if (*curobj == NULL || curkey->keyid != toadd->keyid) {
			keys->next = *curobj;
			*curobj = keys;
		}
		keys = tmp;
	}
	return newll;
}

static void output_key(struct onak_dbctx *dbctx,
		FILE *names, FILE *keys, uint64_t keyid)
{
	fprintf(names, "%s\n", dbctx->keyid2uid(dbctx, keyid));
	fprintf(keys, "%c%c%c%c", (int) (keyid >> 24) & 0xFF,
			(int) (keyid >> 16) & 0xFF,
			(int) (keyid >>  8) & 0xFF,
			(int) (keyid      ) & 0xFF);
}

static void wotsap(struct onak_dbctx *dbctx, uint64_t keyid, char *dir)
{
	struct ll *pending, *sigll, *sigsave;
	uint32_t curidx = 0;
	struct stats_key *curkey, *addkey;
	char *uid;
	FILE *names, *keys, *sigs, *file;
	char *tmppath;
	uint32_t sigcount, sigentry;

	/* Length of dir + "/" + "signatures" + NUL */
	tmppath = malloc(strlen(dir) + 12);

	sprintf(tmppath, "%s/WOTVERSION", dir);
	file = fopen(tmppath, "w");
	if (file == NULL) {
		fprintf(stderr, "Couldn't open %s\n", tmppath);
		return;
	}
	fprintf(file, "0.2\n");
	fclose(file);

	sprintf(tmppath, "%s/README", dir);
	file = fopen(tmppath, "w");
	if (file == NULL) {
		fprintf(stderr, "Couldn't open %s\n", tmppath);
		return;
	}
	fprintf(file, "This is a Web of Trust archive.\n");
	fprintf(file, "The file format is documented at:\n");
	fprintf(file, "  http://www.lysator.liu.se/~jc/wotsap/wotfileformat.txt\n\n");
	fprintf(file, "This file was generated by onak " ONAK_VERSION " \n");
	fclose(file);

	sprintf(tmppath, "%s/names", dir);
	names = fopen(tmppath, "w");
	if (names == NULL) {
		fprintf(stderr, "Couldn't open %s\n", tmppath);
		return;
	}
	sprintf(tmppath, "%s/keys", dir);
	keys = fopen(tmppath, "wb");
	if (keys == NULL) {
		fprintf(stderr, "Couldn't open %s\n", tmppath);
		return;
	}
	sprintf(tmppath, "%s/signatures", dir);
	sigs = fopen(tmppath, "wb");
	if (sigs == NULL) {
		fprintf(stderr, "Couldn't open %s\n", tmppath);
		return;
	}
	free(tmppath);

	dbctx->cached_getkeysigs(dbctx, keyid);
	curkey = findinhash(keyid);
	curkey->colour = ++curidx;
	pending = lladd(NULL, curkey);

	output_key(dbctx, names, keys, curkey->keyid);

	while (pending != NULL) {
		curkey = (struct stats_key *) pending->object;
		sigll = dbctx->cached_getkeysigs(dbctx, curkey->keyid);
		sigsave = sigll = sortkeyll(sigll);
		sigcount = 0;
		while (sigll != NULL) {
			addkey = (struct stats_key *) sigll->object;
			if (addkey->colour == 0 && !addkey->revoked) {
				uid = dbctx->keyid2uid(dbctx, addkey->keyid);
				if (uid != NULL) {
					/* Force it to be loaded so we know if it's revoked */
					dbctx->cached_getkeysigs(dbctx,
							addkey->keyid);
					if (!addkey->revoked) {
						addkey->colour = ++curidx;
						pending = lladdend(pending, addkey);
						output_key(dbctx, names, keys,
							addkey->keyid);
					}
				}
			}
			if (addkey->colour != 0) {
				sigcount++;
			}
			sigll = sigll->next;
		}
		/* Now output the signatures */
		sigcount = htonl(sigcount);
		fwrite(&sigcount, sizeof (sigcount), 1, sigs);
		sigll = sigsave;
		while (sigll != NULL) {
			addkey = (struct stats_key *) sigll->object;
			if (addkey->colour != 0) {
				sigentry = addkey->colour - 1;
				/* Pretend it's on the primary UID for now */
				sigentry |= 0x40000000;
				sigentry = htonl(sigentry);
				fwrite(&sigentry, sizeof (sigentry), 1, sigs);
			}
			sigll = sigll->next;
		}
		pending = pending->next;
	}

	fclose(sigs);
	fclose(keys);
	fclose(names);
}

int main(int argc, char *argv[])
{
	int optchar;
	char *configfile = NULL, *dir = NULL;
	uint64_t keyid = 0x2DA8B985;
	struct onak_dbctx *dbctx;

	while ((optchar = getopt(argc, argv, "c:")) != -1 ) {
		switch (optchar) {
		case 'c':
			configfile = strdup(optarg);
			break;
		}
	}

	if (optind < argc) {
		dir = argv[optind];
	}

	readconfig(configfile);
	initlogthing("wotsap", config.logfile);
	dbctx = config.dbinit(config.backend, true);
	if (dbctx != NULL) {
		inithash();
		wotsap(dbctx, dbctx->getfullkeyid(dbctx, keyid),
			dir ? dir : ".");
		destroyhash();
		dbctx->cleanupdb(dbctx);
	} else {
		fprintf(stderr, "Couldn't initialize key database.\n");
	}
	cleanuplogthing();
	cleanupconfig();
	free(configfile);
}
