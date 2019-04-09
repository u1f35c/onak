/*
 * wordlist.h - Routines for manipulating word lists
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
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef __WORDLIST_H__
#define __WORDLIST_H__

#include "ll.h"
#include "keystructs.h"

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
struct ll *makewordlist(struct ll *wordlist, char *word);

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
			       struct openpgp_publickey *key);

#endif /* __WORDLIST_H__ */
