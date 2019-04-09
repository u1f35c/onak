/*
 * photoid.c - Routines for OpenPGP id photos.
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

#include <stdlib.h>

#include "keystructs.h"
#include "onak.h"
#include "photoid.h"

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
onak_status_t getphoto(struct openpgp_publickey *key, int index,
		unsigned char **photo, size_t *length)
{
	struct openpgp_signedpacket_list *curuid = NULL;
	int                               i = 0;
	int                               j = 0;

	if (key == NULL || photo == NULL || length == NULL)
		return ONAK_E_INVALID_PARAM;

	*photo = NULL;
	
	curuid = key->uids;
	i = 0;
	while (*photo == NULL && curuid != NULL && i <= index) {
		if (curuid->packet->tag == 17) {
			if (i == index) {
				j = 0;
				*length = curuid->packet->data[j++];
				if (*length < 192) {
					/* length is correct */
				} else if (*length < 255) {
					*length -= 192;
					*length <<= 8;
					*length += curuid->packet->data[j++];
					*length +=  192;
				} else {
					*length = curuid->packet->data[j++];
					*length <<= 8;
					*length += curuid->packet->data[j++];
					*length <<= 8;
					*length += curuid->packet->data[j++];
					*length <<= 8;
					*length += curuid->packet->data[j++];
				}
				j++;
				*length -= 17;
				*photo = &(curuid->packet->data[j+16]);
			} else {
				i++;
			}
		}
		curuid = curuid->next;
	}

	return *photo == NULL ? ONAK_E_NOT_FOUND : ONAK_E_OK;
}
