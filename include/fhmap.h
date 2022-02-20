/**
 * @file fhmap.h
 * @brief Hash map with linear probing containing filter entries interface description
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef FHMAP_H
#define FHMAP_H

#include <stddef.h>
#include <stdbool.h>

#include "utils.h"

/**
 * @brief Hashmap with linear probing containing filter entries
 */
struct fhmap {
	/**Capacity of array*/
	size_t cap;
	/**Elements in array*/
	size_t len;
	/**Array of filter entries*/
	struct f_entry **arr;
};

/**
 * @brief Cretes new hashmap with given capacity
 * @param[in] cap Hashmap capacity
 * @return New hashmap if succeded, NULL otherwise
 */
struct fhmap *fhmap_new(size_t cap);

/**
 * @brief Sets filter entry into hashmap if possible
 * @param[in] *map 	Pointer to hashmap to insert value to
 * @param[in] *e 	Filter entry to insert
 * @return STATUS_OK if succeded
 */
status_val fhmap_put(struct fhmap *map, struct f_entry *e);

/**
 * @brief Gets filter entry by tag from hashmap
 * @param[in] *map 	Hashmap to get entry from
 * @param[in] *tag 	Key to hash
 * @param[out] ** 	Pointer to return value
 * @return STATUS_OK if succeded
 */
status_val fhmap_get(struct fhmap *map, const char *tag, struct f_entry **e);

/**
 * @brief Frees hashmap
 * @param[in] *map hashmap to free
 * @return Void
 */
void fhmap_shallow_free(struct fhmap *map);

#endif
