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
 *	lladdend - Add an item to the end of a linked list.
 *	@curll: The list to add to. Can be NULL to create a new list.
 *	@object: The object to add.
 *
 *	Returns a pointer to the head of the new list.
 */
struct ll *lladdend(struct ll *curll, void *object);

/**
 *	lldel - Remove an item from a linked list.
 *	@curll: The list to remove the item from.
 *	@object: The object to remove.
 *	@objectcmp: A pointer to a comparision function for the object type.
 *
 *	Trawls through the list looking for the object. If it's found then it
 *	is removed from the list. Only one occurance is searched for. Returns
 *	a pointer to the head of the new list.
 */
struct ll *lldel(struct ll *curll, void *object,
	int (*objectcmp) (const void *object1, const void *object2));

/**
 *	llfind - Find an item in a linked list.
 *	@curll: The list to look in.
 *	@object: The object to look for.
 *	@objectcmp: A pointer to a comparision function for the object type.
 *
 *	Searches through a list for an object. Returns a pointer to the object
 *	if it's found, otherwise NULL.
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

/**
 *	llfree - Frees a linked list.
 *	@curll: The list to free.
 *	@objectfree: A pointer to a free function for the object.
 *
 * 	Walks through a list and free it. If a function is provided for
 * 	objectfree then it's called for each element to free them, if it's NULL
 * 	just the list is freed.
 */
void llfree(struct ll *curll, void (*objectfree) (void *object));

#endif /* __LL_H__ */
