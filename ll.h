/*
 * ll.h - various things of used for dealing with linked lists.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#ifndef __LL_H__
#define __LL_H__

#define ADD_PACKET_TO_LIST_END(list, name, item)                              \
	if (list->name##s != NULL) {                                          \
		list->last_##name->next = malloc(sizeof (*list->last_##name));\
		list->last_##name = list->last_##name->next;                  \
	} else {                                                              \
		list->name##s = list->last_##name =                           \
			malloc(sizeof (*list->last_##name));                  \
	}                                                                     \
	memset(list->last_##name, 0, sizeof(*list->last_##name));             \
	list->last_##name->packet = item;

#define ADD_PACKET_TO_LIST(list, item)                                        \
	if (list != NULL) {                                                   \
		list->next = malloc(sizeof (*list));                          \
		list = list->next;                                            \
	} else {                                                              \
		list = malloc(sizeof (*list));                                \
	}                                                                     \
	memset(list, 0, sizeof(*list));                                       \
	list->packet = item;

/**
 *	struct ll - A generic linked list structure.
 *	@object: The object.
 *	@next: A pointer to the next object.
 */
struct ll {
	void *object;
	struct ll *next;
};

/**
 *	lladd - Add an item to a linked list.
 *	@curll: The list to add to. Can be NULL to create a new list.
 *	@object: The object to add.
 *
 *	Returns a pointer to the head of the new list.
 */
struct ll *lladd(struct ll *curll, void *object);

/**
 *
 */
struct ll *lldel(struct ll *curll, void *object,
	int (*objectcmp) (const void *object1, const void *object2));

/**
 *
 */
struct ll *llfind(struct ll *curll, void *object,
	int (*objectcmp) (const void *object1, const void *object2));

/**
 *	llsize - Returns the number of elements in a linked list.
 *	@curll: The linked list to count.
 *
 *	Counts the number of elements in a linked list.
 */
unsigned long llsize(struct ll *curll);

#endif /* __LL_H__ */
