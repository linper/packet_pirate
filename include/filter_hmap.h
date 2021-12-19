#ifndef FILTER_HMAP_H
#define FILTER_HMAP_H

#include <stddef.h>
#include <stdbool.h>

#include "utils.h"
#include "filter.h"

struct fhmap {
	size_t cap; //capacity of array
	size_t len; //elements in array
	struct f_entry **arr; //array of filter entries
};

/**
 * @brief Cretes new hashmap with given capacity
 * @param cap Hashmap capacity
 * @return New hashmap if succeded, NULL otherwise
 */
struct fhmap *fhmap_new(size_t cap);

/**
 * @brief Sets filter entry into hashmap if possible
 * @param map Hashmap to insert value to
 * @param e Filter entry to insert
 * @return STATUS_OK if succeded
 */
status_val fhmap_put(struct fhmap *map, struct f_entry *e);

/**
 * @brief Gets filter entry by tag from hashmap
 * @param map Hashmap to get entry from
 * @param tag Key to hash
 * @param e Pointer to return walue
 * @return STATUS_OK if succeded
 */
status_val fhmap_get(struct fhmap *map, const char *tag, struct f_entry **e);

/**
 * @brief Frees hashmap
 * @param map hashmap to free
 * @return Void
 */
void fhmap_free(struct fhmap *map);

#endif
