/*
 * wordlist.h - Routines for manipulating word lists
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2004 Project Purple
 *
 * $Id: wordlist.h,v 1.1 2004/05/27 03:34:35 noodles Exp $
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
