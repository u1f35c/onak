/*
 * wordlist.c - Routines for manipulating word lists
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2004 Project Purple
 *
 * $Id: wordlist.c,v 1.2 2004/05/28 02:55:49 noodles Exp $
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "ll.h"
#include "decodekey.h"
#include "log.h"
#include "wordlist.h"

/**
 *	makewordlist - Takes a string and splits it into a set of unique words.
 *	@wordlist: The current word list.
 *	@words: The string to split and add.
 *
 *	We take words and split it on non alpha numeric characters. These get
 *	added to the word list if they're not already present. If the wordlist
 *	is NULL then we start a new list, otherwise it's search for already
 *	added words. Note that words is modified in the process of scanning.
 *
 *	Returns the new word list.
 */
struct ll *makewordlist(struct ll *wordlist, char *word)
{
	char *start = NULL;
	char *end = NULL;

	/*
	 * Walk through the words string, spliting on non alphanumerics and
	 * then checking if the word already exists in the list. If not then
	 * we add it.
	 */
	end = word;
	while (end != NULL && *end != 0) {
		start = end;
		while (*start != 0 && !isalnum(*start)) {
			start++;
		}
		end = start;
		while (*end != 0 && isalnum(*end)) {
			*end = tolower(*end);
			end++;
		}
		if (end - start > 1) {
			if (*end != 0) {
				*end = 0;
				end++;
			}

			if (llfind(wordlist, start, strcmp) == NULL) {
				wordlist = lladd(wordlist, start);
			}
		}
	}
	return wordlist;
}

/**
 *	makewordlistfromkey - Takes a public key and splits it into a set of 
 *                     unique words.
 *	@wordlist: The current word list.
 *	@key: The key to return the words from.
 *
 *	We take words and split it on non alpha numeric characters. These get
 *	added to the word list if they're not already present. If the wordlist
 *	is NULL then we start a new list, otherwise it's search for already
 *	added words. Note that words is modified in the process of scanning.
 *
 *	Returns the new word list.
 */
struct ll *makewordlistfromkey(struct ll *wordlist,
			       struct openpgp_publickey *key)
{
	char      **uids;
	int         i;
	struct ll  *words = NULL;
	struct ll  *wl = NULL;

	uids = keyuids(key, NULL);
	for (i = 0; uids[i] != NULL; ++i) {
		words = makewordlist(wordlist, uids[i]);
		for (wl = words; wl->next; wl = wl->next) {
			if (llfind(wordlist, wl->object, strcmp) == NULL) {
				wordlist = lladd(wordlist, strdup(wl->object));
			}
		}
		free(uids[i]);
		uids[i] = NULL;
	}
	free(uids);

	return wordlist;
}
