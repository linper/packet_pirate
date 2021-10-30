#ifndef FILTER_HMAP_H
#define FILTER_HMAP_H

#include <stddef.h>
#include <stdbool.h>

#include "utils.h"
#include "filter.h"

//enum map_status {
    //MAP_MISSING = -3,  	[> No such element <]
    //MAP_FULL = -2 ,	[> Hashmap is full <]
    //MAP_OMEM = -1, 	[> Out of Memory <]
    //MAP_OK = 0, 		[> OK <]
//};

struct fhmap {
	size_t cap;
	size_t len;
	struct entry **arr;
};

struct fhmap *fhmap_new(size_t cap);


status_val fhmap_put(struct fhmap *map, struct entry *e);

status_val fhmap_get(struct fhmap *map, const char *tag, struct entry **e);

void fhmap_free(struct fhmap *map);

#endif
