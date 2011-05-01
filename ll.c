/*
 * ll.c - various things of used for dealing with linked lists.
 *
 * Copyright 2000-2004 Jonathan McDowell <noodles@earth.li>
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

#include <stdio.h>
#include <stdlib.h>

#include "ll.h"
#include "log.h"

struct ll *lladd(struct ll *curll, void *object)
{
	struct ll *new;

	if ((new = malloc(sizeof(struct ll))) == NULL) {
		perror("lladd()");
		printf("Got NULL in lladd()\n");
		return NULL;
	}

	new->next = curll;
	new->object = object;

	return new;
}

struct ll *lladdend(struct ll *curll, void *object)
{
	struct ll *new;
	struct ll *cur;

	if ((new = malloc(sizeof(struct ll))) == NULL) {
		logthing(LOGTHING_ERROR,
				"Couldn't allocate memory in lladdend()");
		return NULL;
	}

	new->next = NULL;
	new->object = object;

	if (curll != NULL) {
		cur = curll;
		while (cur->next != NULL) {
			cur = cur->next;
		}
		cur->next = new;
	} else {
		curll = new;
	}
	
	return curll;
}

struct ll *lldel(struct ll *curll, void *object,
	int (*objectcmp) (const void *object1, const void *object2))
{
	struct ll *cur = NULL;
	struct ll *old = NULL;

	log_assert(objectcmp != NULL);

	cur = curll;
	if (cur == NULL) {
		return NULL;
	} else if (!(*objectcmp)(cur->object, object)) {
		old = cur;
		cur = cur->next;
		free(old);
		return cur;
	} 
	while (cur->next != NULL) {
		if (!(*objectcmp)(cur->next->object, object)) {
			old = cur->next;
			cur->next = cur->next->next;
			free(old);
			break;
		}
	}
	return curll;
}

struct ll *llfind(struct ll *curll, void *object,
	int (*objectcmp) (const void *object1, const void *object2))
{
	struct ll *cur;

	log_assert(objectcmp != NULL);

	cur = curll;
	while (cur != NULL && (*objectcmp)(cur->object, object)) {
		cur = cur->next;
	}
	return cur;
}

unsigned long llsize(struct ll *curll)
{
	unsigned long count = 0;

	while (curll != NULL) {
		count++;
		curll = curll->next;
	}

	return count;
}

/**
 *	llfree - Frees a linked list.
 *	@curll: The list to free.
 *	@objectfree: A pointer to a free function for the object.
 *
 * 	Walks through a list and free it. If a function is provided for
 * 	objectfree then it's called for each element to free them, if it's NULL
 * 	just the list is freed.
 */
void llfree(struct ll *curll, void (*objectfree) (void *object))
{
	struct ll *nextll;

	while (curll != NULL) {
		nextll = curll->next;
		if (curll->object != NULL && objectfree != NULL) {
			objectfree(curll->object);
			curll->object = NULL;
		}
		free(curll);
		curll = nextll;
	}
	return;
}
