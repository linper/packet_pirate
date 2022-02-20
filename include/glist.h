/**
 * @file glist.h
 * @brief Description of generic list data structure interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef GLIST_H
#define GLIST_H

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stddef.h>

#include "utils.h"

/**
 * @brief Implementation of generic list data structure
 */
struct glist {
	/**Internal array to store data pointers*/
	void **array;
	/**Number of data entries currently stored*/
	size_t count;
	/**Maximum capacity of internal array*/
	size_t cap;
	/**Callback function to be called for each entry when freeing or clearing*/
	void (*free_cb)(void *);
};

/**
 * @brief Creates glist struct with specified initial capacity
 * @param[in] cap 	Initial capacity. It must be power of 2 
 * and highier than 0, if not defaults to 16
 * @return Pointer to created glist struct if successful, NULL otherwise  
 */
struct glist *glist_new(int cap);

/**
 * @brief Cleares glist struct and and frees its entries by issuing
 * free() for each of them or free callback function instead.
 * If it was registered to list instance
 * @param[in, out] *lst	Pointer to list to clear
 * @return Void
 */
void glist_clear(struct glist *lst);

/**
 * @brief Cleares glist struct by seting its item count to 0.
 * Does not free its entries
 * @param[in, out] *lst Pointer to list to clear
 * @return Void
 */
void glist_clear_shallow(struct glist *lst);

/**
 * @brief Frees glist struct and its entries by issuing
 * free() for each of them or free callback function instead.
 * If it was registered to list instance
 * @param[in] *lst 	Pointer to list to free
 * @return Void
 */
void glist_free(struct glist *lst);

/**
 * @brief Frees glist struct but leaves its entries intact
 * @param[in] *lst 	Pointer to list to free
 * @return Void
 */
void glist_free_shallow(struct glist *lst);

/**
 * @brief Appends item  at the end of list
 * @param[in] *lst 		List pointer to append item to
 * @param[in] *value 	Item poiinter to append to list
 * @return STATUS_OK if successful
 */
status_val glist_push(struct glist *lst, void *value);

/**
 * @brief Gets item from list at specific index
 * @param[in] *lst 		List pointer to retrieve item from
 * @param[in] index 	Index to get item at
 * @param[out] **value 	Double pointer to return item
 * @return STATUS_OK if successful
 */
status_val glist_get(struct glist *lst, int index, void **value);

/**
 * @brief Function copies entriies from one list to another
 * @param[in] *src 			Pointer to list to copy entries from 
 * @param[in, out] *dst 	Pointer to list to copy entries to
 * @return STATUS_OK on successful
 */
status_val glist_copy_to(struct glist *src, struct glist *dst);

/**
 * @brief Gets nubmer of items stored in glist
 * @param[in] *lst 	List pointer to get entry count from
 * @return Number of entries currently stored
 */
size_t glist_count(struct glist *lst);

/**
 * @brief Sets callback function for list to be called instead
 * of free() for every data entry when freeing list (or similar)
 * @param[in] *lst 	List pointer to add callback to
 * @param[in] *cb 	Callback function, free() replacement.
 * @return Void
 */
void glist_set_free_cb(struct glist *lst, void (*cb)(void *));

/**
 * @brief Iterator for glist struct
 * @param[out] *item Entry pointer of current iteration
 * @param[in] *list Pointer to list to iterate
 */
#define glist_foreach(item, list)                                              \
	for (int keep = 1, count = 0, size = list->count; keep && count != size;   \
		 keep = !keep, count++)                                                \
		for (item = *(list->array + count); keep; keep = !keep)

#endif
