/*
 * wordlist.c - Routines for manipulating word lists
 *
 * Copyright 2004 Jonathan McDowell <noodles@earth.li>
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
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ll.h"
#include "decodekey.h"
#include "keystructs.h"
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
		while (*start != 0 && (ispunct(*start) || isspace (*start))) {
			start++;
		}
		end = start;
		while (*end != 0 && (!ispunct(*end) && !isspace (*end))) {
			*end = tolower(*end);
			end++;
		}
		if (end - start > 1) {
			if (*end != 0) {
				*end = 0;
				end++;
			}

			if (llfind(wordlist, start, 
				(int (*)(const void *, const void *)) strcmp
					) == NULL) {
				wordlist = lladdend(wordlist, start);
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
	for (i = 0; uids != NULL && uids[i] != NULL; ++i) {
		words = makewordlist(NULL, uids[i]);
		for (wl = words; wl != NULL; wl = wl->next) {
			if (llfind(wordlist, wl->object, 
				(int (*)(const void *, const void *)) strcmp
						) == NULL) {
				wordlist = lladd(wordlist, strdup(wl->object));
			}
		}
		free(uids[i]);
		uids[i] = NULL;
	}
	free(uids);

	return wordlist;
}
