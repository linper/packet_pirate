/**
 * @file fhmap.c
 * @brief Hash map with linear probing containing filter entries implementation
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include "../include/filter.h"
#include "../include/fhmap.h"

/**
 * @brief Hashing algorithm: djb2
 * @param *str string to hash
 * @return Hash value
 */
static unsigned long hash_val(const char *str)
{
	unsigned long hash = 5381;
	int c;
	while ((c = *str++))
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	return hash;
}

struct fhmap *fhmap_new(size_t cap)
{
	struct fhmap *m = (struct fhmap *)malloc(sizeof(struct fhmap));
	if (!m) {
		LOG(L_CRIT, STATUS_OMEM);
		goto err;
	}

	m->arr = (struct f_entry **)calloc(cap, sizeof(struct f_entry *));

	if (!m->arr) {
		LOG(L_CRIT, STATUS_OMEM);
		goto err;
	}

	m->cap = cap;
	m->len = 0;

	return m;
err:
	if (m) {
		fhmap_shallow_free(m);
	}

	return NULL;
}

status_val fhmap_put(struct fhmap *map, struct f_entry *e)
{
	unsigned idx = hash_val(e->tag) % map->cap;

	if (map->cap == map->len) {
		LOG(L_WARN, STATUS_FULL);
		return STATUS_FULL;
	}

	while (map->arr[idx]) { //linear probing
		idx = (idx + 1) % map->cap;
	}

	map->arr[idx] = e;
	map->len++;

	return STATUS_OK;
}

status_val fhmap_get(struct fhmap *map, const char *key, struct f_entry **e)
{
	int idx = hash_val(key) % map->cap;

	for (size_t i = 0; i < map->cap; i++) {
		if (map->arr[idx] && !strcmp(map->arr[idx]->tag, key)) {
			*e = map->arr[idx];
			return STATUS_OK;
		}

		idx = (idx + 1) % map->cap;
	}

	*e = NULL;
	LOG(L_NOTICE, STATUS_NOT_FOUND);
	return STATUS_NOT_FOUND;
}

void fhmap_shallow_free(struct fhmap *map)
{
	if (map) {
		free(map->arr);
		free(map);
	}
}
