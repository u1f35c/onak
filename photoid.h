/*
 * photoid.h - Routines for OpenPGP id photos.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2004 Project Purple
 *
 * $Id: photoid.h,v 1.2 2004/05/27 21:58:18 noodles Exp $
 */

#ifndef __PHOTOID_H__
#define __PHOTOID_H__

#include "keystructs.h"

/**
 * 	getphoto - returns an OpenPGP packet containing a photo id.
 * 	@key: The key to return the photo id from.
 * 	@index: The index of the photo to return.
 * 	@photo: The photo data.
 * 	@length: The length of the photo data.
 *
 * 	This function returns the photo data contained in a supplied key.
 * 	index specifies which photo id should be returned. If there's no such
 * 	photo id NULL is returned. The returned data pointer refers to the key
 * 	data supplied rather than a copy of it.
 */
int getphoto(struct openpgp_publickey *key, int index, unsigned char **photo,
		size_t *length);

#endif /* __PHOTOID_H__ */
