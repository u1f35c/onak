/*
 * keyarray.c - routines to maintain a sorted array of keyids.
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyarray.h"

bool array_find(struct keyarray *array, uint64_t key)
{
	bool found;
	int  top = 0;
	int  bottom = 0;
	int  curpos;

	found = false;
	if (array->keys != NULL && array->count > 0) {
		bottom = -1;
		top = array->count - 1;
		while ((top - bottom) > 1) {
			curpos = (top + bottom) / 2;
			if (key > array->keys[curpos]) {
				bottom = curpos;
			} else {
				top = curpos;
			}
		}
		found = (array->keys[top] == key);
	}

	return found;
}

bool array_add(struct keyarray *array, uint64_t key)
{
	bool found;
	int  top = 0;
	int  bottom = 0;
	int  curpos = 0;

	found = false;
	if (array->keys != NULL && array->count > 0) {
		bottom = -1;
		top = array->count - 1;
		while ((top - bottom) > 1) {
			curpos = (top + bottom) / 2;
			if (key > array->keys[curpos]) {
				bottom = curpos;
			} else {
				top = curpos;
			}
		}
		found = (array->keys[top] == key);

		if (key > array->keys[top]) {
			curpos = top + 1;
		} else {
			curpos = top;
		}
	}

	if (!found) {
		if (array->size == 0) {
			array->keys = malloc(16 * sizeof(uint64_t));
			array->size = 16;
			array->count = 1;
			array->keys[0] = key;
		} else {
			if (array->count >= array->size) {
				array->size *= 2;
				array->keys = realloc(array->keys,
						array->size * sizeof(uint64_t));
			}
			if (curpos < array->count) {
				memmove(&array->keys[curpos+1],
					&array->keys[curpos],
					sizeof(uint64_t) *
						(array->count - curpos));
			}
			array->keys[curpos] = key;
			array->count++;
		}
	}

	return !found;
}

void array_free(struct keyarray *array)
{
	if (array->keys) {
		free(array->keys);
		array->keys = NULL;
	}
	array->count = array->size = 0;

	return;
}
