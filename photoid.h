/*
 * photoid.h - Routines for OpenPGP id photos.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2004 Project Purple
 *
 * $Id: photoid.h,v 1.1 2004/05/27 01:25:37 noodles Exp $
 */

#ifndef __PHOTOID_H__
#define __PHOTOID_H__

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
struct openpgp_packet *getphoto(struct openpgp_publickey *key, int index);

#endif /* __PHOTOID_H__ */
