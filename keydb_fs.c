/*
 * keydb.h - Routines to store and fetch keys.
 *
 * Daniel Silverstone <dsilvers@digital-scurf.org>
 *
 * Copyright 2004 Daniel Silverstone and Project Purple
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>

#include "charfuncs.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "ll.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"
#include "log.h"
#include "wordlist.h"

static int keydb_lockfile_fd = -1;
static bool keydb_lockfile_readonly;

/*****************************************************************************/

/* Helper functions */

#define FNV_offset_basis 2166136261ul
#define FNV_mixing_prime 16777619ul

static uint32_t calchash(uint8_t * ptr)
{
	register uint32_t h = FNV_offset_basis;
	register uint32_t p = FNV_mixing_prime;
	register uint32_t n = strlen((char *) ptr);
	register uint8_t *c = ptr;
	while (n--) {
		h *= p;
		h ^= *c++;
	}
	return h ? h : 1;	/* prevent a hash of zero happening */
}


void keypath(char *buffer, uint64_t _keyid)
{
	uint64_t keyid = _keyid << 32;
	snprintf(buffer, PATH_MAX, "%s/key/%02X/%02X/%08X/%016llX",
		 config.db_dir, (uint8_t) ((keyid >> 56) & 0xFF),
		 (uint8_t) ((keyid >> 48) & 0xFF),
		 (uint32_t) (keyid >> 32), _keyid);
}

void keydir(char *buffer, uint64_t _keyid)
{
	uint64_t keyid = _keyid << 32;
	snprintf(buffer, PATH_MAX, "%s/key/%02X/%02X/%08X", config.db_dir,
		 (uint8_t) ((keyid >> 56) & 0xFF),
		 (uint8_t) ((keyid >> 48) & 0xFF),
		 (uint32_t) (keyid >> 32));
}

void prove_path_to(uint64_t keyid, char *what)
{
	static char buffer[1024];
	snprintf(buffer, PATH_MAX, "%s/%s", config.db_dir, what);
	mkdir(buffer, 0777);

	snprintf(buffer, PATH_MAX, "%s/%s/%02X", config.db_dir, what,
		 (uint8_t) ((keyid >> 24) & 0xFF));
	mkdir(buffer, 0777);

	snprintf(buffer, PATH_MAX, "%s/%s/%02X/%02X", config.db_dir, what,
		 (uint8_t) ((keyid >> 24) & 0xFF),
		 (uint8_t) ((keyid >> 16) & 0xFF));
	mkdir(buffer, 0777);

	snprintf(buffer, PATH_MAX, "%s/%s/%02X/%02X/%08X", config.db_dir, what,
		 (uint8_t) ((keyid >> 24) & 0xFF),
		 (uint8_t) ((keyid >> 16) & 0xFF), (uint32_t) (keyid));
	mkdir(buffer, 0777);
}

void wordpath(char *buffer, char *word, uint32_t hash, uint64_t keyid)
{
	snprintf(buffer, PATH_MAX, "%s/words/%02X/%02X/%08X/%s/%016llX",
		 config.db_dir, (uint8_t) ((hash >> 24) & 0xFF),
		 (uint8_t) ((hash >> 16) & 0xFF), hash, word, keyid);
}

void worddir(char *buffer, char *word, uint32_t hash)
{
	snprintf(buffer, PATH_MAX, "%s/words/%02X/%02X/%08X/%s", config.db_dir,
		 (uint8_t) ((hash >> 24) & 0xFF),
		 (uint8_t) ((hash >> 16) & 0xFF), hash, word);
}

/*****************************************************************************/

/**
 *	initdb - Initialize the key database.
 */
void initdb(bool readonly)
{
	char buffer[PATH_MAX];

	keydb_lockfile_readonly = readonly;

	snprintf(buffer, PATH_MAX, "%s/.lock", config.db_dir);

	if (access(config.db_dir, R_OK | W_OK | X_OK) == -1) {
		if (errno != ENOENT) {
			logthing(LOGTHING_CRITICAL,
				 "Unable to access keydb_fs root of '%s'. (%s)",
				 config.db_dir, strerror(errno));
			exit(1);	/* Lacking rwx on the key dir */
		}
		mkdir(config.db_dir, 0777);
		keydb_lockfile_fd = open(buffer, O_RDWR | O_CREAT, 0600);
	}
	chdir(config.db_dir);
	if (keydb_lockfile_fd == -1)
		keydb_lockfile_fd = open(buffer,
					 (keydb_lockfile_readonly) ?
					 O_RDONLY : O_RDWR);
	if (keydb_lockfile_fd == -1)
		keydb_lockfile_fd = open(buffer, O_RDWR | O_CREAT, 0600);
	if (keydb_lockfile_fd == -1) {
		logthing(LOGTHING_CRITICAL,
			 "Unable to open lockfile '%s'. (%s)",
			 buffer, strerror(errno));
		exit(1);	/* Lacking rwx on the key dir */
	}
}

/**
 *	cleanupdb - De-initialize the key database.
 */
void cleanupdb(void)
{
	/* Mmmm nothing to do here? */
	close(keydb_lockfile_fd);
}

/**
 *	starttrans - Start a transaction.
 */
bool starttrans(void)
{
	struct flock lockstruct;
	int remaining = 20;
	lockstruct.l_type =
	    F_RDLCK | ((keydb_lockfile_readonly) ? 0 : F_WRLCK);
	lockstruct.l_whence = SEEK_SET;
	lockstruct.l_start = 0;
	lockstruct.l_len = 1;

	while (fcntl(keydb_lockfile_fd, F_SETLK, &lockstruct) == -1) {
		if (remaining-- == 0)
			return false;	/* Hope to hell that noodles DTRT */
		usleep(100);
	}
	return true;
}

/**
 *	endtrans - End a transaction.
 */
void endtrans(void)
{
	struct flock lockstruct;

	lockstruct.l_type = F_UNLCK;
	lockstruct.l_whence = SEEK_SET;
	lockstruct.l_start = 0;
	lockstruct.l_len = 1;
	fcntl(keydb_lockfile_fd, F_SETLK, &lockstruct);
}

/**
 *	fetch_key - Given a keyid fetch the key from storage.
 *	@keyid: The keyid to fetch.
 *	@publickey: A pointer to a structure to return the key in.
 *	@intrans: If we're already in a transaction.
 */
int fetch_key(uint64_t keyid, struct openpgp_publickey **publickey,
	      bool intrans)
{
	static char buffer[PATH_MAX];
	int ret = 0, fd;
	struct openpgp_packet_list *packets = NULL;

	if (!intrans)
		starttrans();

	if ((keyid >> 32) == 0)
		keyid = getfullkeyid(keyid);

	keypath(buffer, keyid);
	if ((fd = open(buffer, O_RDONLY)) != -1) {
		/* File is present, load it in... */
		read_openpgp_stream(file_fetchchar, &fd, &packets, 0);
		parse_keys(packets, publickey);
		free_packet_list(packets);
		packets = NULL;
		close(fd);
		ret = 1;
	}

	if (!intrans)
		endtrans();
	return ret;
}

/**
 *	store_key - Takes a key and stores it.
 *	@publickey: A pointer to the public key to store.
 *	@intrans: If we're already in a transaction.
 *	@update: If true the key exists and should be updated.
 */
int store_key(struct openpgp_publickey *publickey, bool intrans,
	      bool update)
{
	static char buffer[PATH_MAX];
	static char wbuffer[PATH_MAX];
	int ret = 0, fd;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct openpgp_publickey *next = NULL;
	uint64_t keyid = get_keyid(publickey);
	struct ll *wordlist = NULL, *wl = NULL;


	if (!intrans)
		starttrans();

	prove_path_to(keyid, "key");
	keypath(buffer, keyid);

	if ((fd =
	     open(buffer, O_WRONLY | (update ? O_TRUNC : O_CREAT),
		  0644)) != -1) {
		next = publickey->next;
		publickey->next = NULL;
		flatten_publickey(publickey, &packets, &list_end);
		publickey->next = next;

		write_openpgp_stream(file_putchar, &fd, packets);
		close(fd);
		free_packet_list(packets);
		packets = NULL;
		ret = 1;
	}

	if (ret) {
		wl = wordlist = makewordlistfromkey(wordlist, publickey);
		while (wl) {
			uint32_t hash = calchash((uint8_t *) (wl->object));
			prove_path_to(hash, "words");

			worddir(wbuffer, wl->object, hash);
			mkdir(wbuffer, 0777);
			wordpath(wbuffer, wl->object, hash, keyid);
			link(buffer, wbuffer);

			wl = wl->next;
		}

		llfree(wordlist, free);
	}

	if (!intrans)
		endtrans();
	return ret;
}

/**
 *	delete_key - Given a keyid delete the key from storage.
 *	@keyid: The keyid to delete.
 *	@intrans: If we're already in a transaction.
 */
int delete_key(uint64_t keyid, bool intrans)
{
	static char buffer[PATH_MAX];
	int ret;
	struct openpgp_publickey *pk = NULL;
	struct ll *wordlist = NULL, *wl = NULL;

	if ((keyid >> 32) == 0)
		keyid = getfullkeyid(keyid);

	if (!intrans)
		starttrans();

	ret = fetch_key(keyid, &pk, true);

	if (ret) {
		logthing(LOGTHING_CRITICAL, "Wordlist for key %016llX",
			 keyid);
		wl = wordlist = makewordlistfromkey(wordlist, pk);
		logthing(LOGTHING_CRITICAL,
			 "Wordlist for key %016llX done", keyid);
		while (wl) {
			uint32_t hash = calchash((uint8_t *) (wl->object));
			prove_path_to(hash, "words");

			wordpath(buffer, wl->object, hash, keyid);
			unlink(buffer);

			wl = wl->next;
		}
	}

	keypath(buffer, keyid);
	unlink(buffer);

	if (!intrans)
		endtrans();
	return 1;
}

static struct ll *internal_get_key_by_word(char *word, struct ll *mct)
{
	struct ll *keys = NULL;
	DIR *d = NULL;
	char buffer[PATH_MAX];
	uint32_t hash = calchash((uint8_t *) (word));
	struct dirent *de;

	worddir(buffer, word, hash);
	d = opendir(buffer);
	logthing(LOGTHING_CRITICAL, "Scanning for word %s in dir %s", word,
		 buffer);
	if (d)
		do {
			de = readdir(d);
			if (de && de->d_name[0] != '.') {
				if ((!mct)
				    || (llfind(mct, de->d_name,
					(int (*)(const void *, const void *))
						    strcmp) !=
					NULL)) {
					logthing(LOGTHING_CRITICAL,
						 "Found %s // %s", word,
						 de->d_name);
					keys =
					    lladd(keys,
						  strdup(de->d_name));
				}
			}
		} while (de);
	closedir(d);

	return keys;
}

/*
 *	fetch_key_text - Trys to find the keys that contain the supplied text.
 *	@search: The text to search for.
 *	@publickey: A pointer to a structure to return the key in.
 */
int fetch_key_text(const char *search,
		   struct openpgp_publickey **publickey)
{
	struct ll *wordlist = NULL, *wl = NULL;
	struct ll *keylist = NULL;
	char      *searchtext = NULL;
	int addedkeys = 0;

	logthing(LOGTHING_CRITICAL, "Search was '%s'", search);

	searchtext = strdup(search);
	wl = wordlist = makewordlist(wordlist, searchtext);

	keylist = internal_get_key_by_word(wordlist->object, NULL);

	if (!keylist) {
		llfree(wordlist, NULL);
		free(searchtext);
		searchtext = NULL;
		return 0;
	}

	wl = wl->next;
	while (wl) {
		struct ll *nkl =
		    internal_get_key_by_word(wl->object, keylist);
		if (!nkl) {
			llfree(wordlist, NULL);
			llfree(keylist, free);
			free(searchtext);
			searchtext = NULL;
			return 0;
		}
		llfree(keylist, free);
		keylist = nkl;
		wl = wl->next;
	}

	llfree(wordlist, NULL);

	/* Now add the keys... */
	wl = keylist;
	while (wl) {
		logthing(LOGTHING_CRITICAL, "Adding key: %s", wl->object);
		addedkeys +=
		    fetch_key(strtoull(wl->object, NULL, 16), publickey,
			      false);
		if (addedkeys >= config.maxkeys)
			break;
		wl = wl->next;
	}

	llfree(keylist, free);
	free(searchtext);
	searchtext = NULL;

	return addedkeys;
}

/*
 *	dumpdb - dump the key database
 *	@filenamebase: The base filename to use for the dump.
 */
int dumpdb(char *filenamebase)
{
	return 0;
}

uint64_t getfullkeyid(uint64_t keyid)
{
	static char buffer[PATH_MAX];
	DIR *d;
	struct dirent *de;
	uint64_t ret = 0;

	keydir(buffer, keyid);

	d = opendir(buffer);
	do {
		de = readdir(d);
		if (de)
			if (de && de->d_name[0] != '.') {
				ret = strtoull(de->d_name, NULL, 16);
			}
	} while (de && de->d_name[0] == '.');
	closedir(d);
	return ret;
}

/*
 * Include the basic keydb routines.
 */
#define NEED_KEYID2UID 1
#define NEED_GETKEYSIGS 1
#include "keydb.c"
