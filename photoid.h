/*
 * photoid.h - Routines for OpenPGP id photos.
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
