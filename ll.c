/*
 * ll.c - various things of used for dealing with linked lists.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2000-2002 Project Purple
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "ll.h"

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

struct ll *lldel(struct ll *curll, void *object,
	int (*objectcmp) (const void *object1, const void *object2))
{
	struct ll *cur = NULL;
	struct ll *old = NULL;

	assert(objectcmp != NULL);

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

	assert(objectcmp != NULL);

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
struct ll *llfree(struct ll *curll,
	void (*objectfree) (void *object))
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
	return NULL;
}
