/*
 * keyarray.h - routines to maintain a sorted array of keyids.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2004 Project Purple
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
