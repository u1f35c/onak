/*
 * keyarray.c - routines to maintain a sorted array of keyids.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2004 Project Purple
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
