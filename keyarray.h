/*
 * keyarray.h - routines to maintain a sorted array of keyids.
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

struct keyarray {
	uint64_t *keys;
	size_t count;
	size_t size;
};

bool array_find(struct keyarray *array, uint64_t key);
void array_free(struct keyarray *array);
bool array_add(struct keyarray *array, uint64_t key);

#endif /* __KEYARRAY_H__ */
