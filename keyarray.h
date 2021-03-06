/**
 * @file keyarray.h
 * @brief Routines to maintain a sorted array of keyids.
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

#ifndef __KEYARRAY_H__
#define __KEYARRAY_H__

#include <stdbool.h>
#include <stdint.h>

#include "keystructs.h"

/**
 * @brief A sorted array of fingerprints
 *
 * Holds a sorted list of fingerprints, with room for growth - has details of
 * both the total size of the array as well as the current number of elements.
 */
struct keyarray {
	/** The array of key fingerprints */
	struct openpgp_fingerprint *keys;
	/** Number of fingerprints in the array */
	size_t count;
	/** Total size of the array */
	size_t size;
};

/**
 * @brief Given a key array figure out of a key id is present
 * @param array Pointer to the key array
 * @param key The keyid to look for
 */
bool array_find(struct keyarray *array, struct openpgp_fingerprint *fp);

/**
 * @brief Free a key array
 * @param array Pointer to the key array to free
 */
void array_free(struct keyarray *array);

/**
 * @brief Add a keyid to a key array
 * @param array Pointer to the key array
 * @param key The keyid to add
 *
 * Checks if the key already exists in the key array and if not adds it.
 * Returns true if the key was added, false if it was found to be already
 * present.
 */
bool array_add(struct keyarray *array, struct openpgp_fingerprint *fp);

/**
 * @brief Load a file into a keyarray
 * @param array Pointer to the key array
 * @param file The full path to the file to load
 *
 * Loads fingerprints from the supplied file into the provided keyarray. Does
 * not re-initialise the array so can be called repeatedly to add multiple
 * files. The file does not need to be sorted; array_add() is called for each
 * key to ensure the array is suitable for binary searching with array_find()
 */
bool array_load(struct keyarray *array, const char *file);

/**
 * @brief Compare two OpenPGP fingerprints
 * @param a Fingerprint 1
 * @param b Fingerprint 2
 *
 * Compares 2 OpenPGP fingerprints, returning an integer less than, equal to,
 * or greater than zero depending on whether a is less than, matches, or is
 * greater than b.
 *
 * For the purposes of comparison shorter fingerprints sort earlier than
 * longer fingerprints (i.e. v3 < v4 < v5) and comparison of same-length
 * fingerprints treats them as a numberical value.
 */
int fingerprint_cmp(struct openpgp_fingerprint *a,
		struct openpgp_fingerprint *b);

#endif /* __KEYARRAY_H__ */
