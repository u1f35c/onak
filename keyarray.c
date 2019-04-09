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
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyarray.h"
#include "keystructs.h"

int fingerprint_cmp(struct openpgp_fingerprint *a,
		struct openpgp_fingerprint *b)
{
	if (a->length < b->length) {
		return -1;
	} else if (a->length > b->length) {
		return 1;
	} else {
		return memcmp(a->fp, b->fp, a->length);
	}
}

bool array_find(struct keyarray *array, struct openpgp_fingerprint *fp)
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
			if (fingerprint_cmp(fp, &array->keys[curpos]) > 0) {
				bottom = curpos;
			} else {
				top = curpos;
			}
		}
		found = (fingerprint_cmp(fp, &array->keys[top]) == 0);
	}

	return found;
}

bool array_add(struct keyarray *array, struct openpgp_fingerprint *fp)
{
	bool found;
	int  top = 0;
	int  bottom = 0;
	int  curpos = 0;

	found = false;
	if (array->size != 0 && array->count > 0) {
		bottom = -1;
		top = array->count - 1;
		while ((top - bottom) > 1) {
			curpos = (top + bottom) / 2;
			if (fingerprint_cmp(fp, &array->keys[curpos]) > 0) {
				bottom = curpos;
			} else {
				top = curpos;
			}
		}
		found = (fingerprint_cmp(fp, &array->keys[top]) == 0);

		if (fingerprint_cmp(fp, &array->keys[top]) > 0) {
			curpos = top + 1;
		} else {
			curpos = top;
		}
	}

	if (!found) {
		if (array->size == 0) {
			array->keys = malloc(16 *
				sizeof(struct openpgp_fingerprint));
			array->size = 16;
			array->count = 1;
			array->keys[0] = *fp;
		} else {
			if (array->count >= array->size) {
				array->size *= 2;
				array->keys = realloc(array->keys,
					array->size *
					sizeof(struct openpgp_fingerprint));
			}
			if (curpos < array->count) {
				memmove(&array->keys[curpos+1],
					&array->keys[curpos],
					sizeof(struct openpgp_fingerprint) *
						(array->count - curpos));
			}
			array->keys[curpos] = *fp;
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
