/**
 * @file ll.h
 * @brief Various things of used for dealing with linked lists.
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

#ifndef __LL_H__
#define __LL_H__

#include <stdlib.h>

/**
 * @brief Take a packet and add it to a linked list
 */
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

/**
 * @brief Add an item to the end of a linked list
 * @param list A pointer to the last element in the list
 * @param item the item to add
 */
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
 * @brief A generic linked list structure.
 */
struct ll {
	/** The object. */
	void *object;
	/** A pointer to the next object. */
	struct ll *next;
};

/**
 * @brief Add an item to a linked list.
 * @param curll The list to add to. Can be NULL to create a new list.
 * @param object The object to add.
 *
 * Returns a pointer to the head of the new list.
 */
struct ll *lladd(struct ll *curll, void *object);

/**
 * @brief Add an item to the end of a linked list.
 * @param curll The list to add to. Can be NULL to create a new list.
 * @param object The object to add.
 *
 * Returns a pointer to the head of the new list.
 */
struct ll *lladdend(struct ll *curll, void *object);

/**
 * @brief Remove an item from a linked list.
 * @param curll The list to remove the item from.
 * @param object The object to remove.
 * @param objectcmp A pointer to a comparision function for the object type.
 *
 * Trawls through the list looking for the object. If it's found then it
 * is removed from the list. Only one occurance is searched for. Returns
 * a pointer to the head of the new list.
 */
struct ll *lldel(struct ll *curll, void *object,
	int (*objectcmp) (const void *object1, const void *object2));

/**
 * @brief Find an item in a linked list.
 * @param curll The list to look in.
 * @param object The object to look for.
 * @param objectcmp A pointer to a comparision function for the object type.
 *
 * Searches through a list for an object. Returns a pointer to the object
 * if it's found, otherwise NULL.
 */
struct ll *llfind(struct ll *curll, void *object,
	int (*objectcmp) (const void *object1, const void *object2));

/**
 * @brief Returns the number of elements in a linked list.
 * @param curll The linked list to count.
 *
 * Counts the number of elements in a linked list.
 */
unsigned long llsize(struct ll *curll);

/**
 * @brief Frees a linked list.
 * @param curll The list to free.
 * @param objectfree A pointer to a free function for the object.
 *
 * Walks through a list and free it. If a function is provided for
 * objectfree then it's called for each element to free them, if it's NULL
 * just the list is freed.
 */
void llfree(struct ll *curll, void (*objectfree) (void *object));

#endif /* __LL_H__ */
