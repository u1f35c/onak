/*
 * photoid.c - Routines for OpenPGP id photos.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2004 Project Purple
 *
 * $Id: photoid.c,v 1.1 2004/05/27 01:25:37 noodles Exp $
 */

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "keyid.h"
#include "keyindex.h"
#include "keystructs.h"

/**
 * 	getphoto - returns an OpenPGP packet containing a photo id.
 * 	@key: The key to return the photo id from.
 * 	@index: The index of the photo to return.
 *
 * 	This function returns the OpenPGP packet containing a photo id from a
 * 	supplied key. index specifies which photo id should be returned. If
 * 	there's no such photo id NULL is returned.
 */
struct openpgp_packet *getphoto(struct openpgp_publickey *key, int index)
{
	struct openpgp_signedpacket_list *curuid = NULL;
	struct openpgp_packet            *photo = NULL;
	int                               i = 0;

	assert(key != NULL);

	curuid = key->uids;
	i = 0;
	while (photo == NULL && curuid != NULL && i <= index) {
		if (curuid->packet->tag == 17) {
			if (i == index) {
				photo = curuid->packet;
			} else {
				i++;
			}
		}
		curuid = curuid->next;
	}

	return photo;
}
