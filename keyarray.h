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
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __KEYARRAY_H__
#define __KEYARRAY_H__

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief A sorted array of keyids
 *
 * Holds a sorted list of keyids, with room for growth - has details of both
 * the total size of the array as well as the current number of elements.
 */
struct keyarray {
	/** The array of key ids */
	uint64_t *keys;
	/** Number of key ids in the array */
	size_t count;
	/** Total size of the array */
	size_t size;
};

/**
 * @brief Given a key array figure out of a key id is present
 * @param array Pointer to the key array
 * @param key The keyid to look for
 */
bool array_find(struct keyarray *array, uint64_t key);

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
bool array_add(struct keyarray *array, uint64_t key);

#endif /* __KEYARRAY_H__ */
