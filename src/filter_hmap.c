#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "../include/filter_hmap.h"


// djb2 hashing
static unsigned long hash_val(const char* str)
{
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}

struct fhmap *fhmap_new(size_t cap)
{
    struct fhmap* m = (struct fhmap*) malloc(sizeof(struct fhmap));
    if(!m) {
        goto err;
    }

    m->arr = (struct entry**) calloc(cap, sizeof(struct entry*));

    if(!m->arr) {
        goto err;
    }

    m->cap = cap;
    m->len = 0;

    return m;
err:
    if (m) {
        fhmap_free(m);
    }
    return NULL;
}

status_val fhmap_put(struct fhmap *map, struct entry *e)
{
    size_t idx = hash_val(e->tag) % map->cap;

    if (map->cap == map->len) {
        return STATUS_FULL;
    }

    while (map->arr[idx]) {
        idx = (idx + 1) % map->cap;
    }

    map->arr[idx] = e;
    map->len++;

    return STATUS_OK;
}

status_val fhmap_get(struct fhmap *map, const char *key, struct entry **e)
{
    int idx = hash_val(key) % map->cap;

    for(size_t i = 0; i < map->cap; i++){
        if(map->arr[idx] && map->arr[idx]->tag == key){
            *e = map->arr[idx];
            return STATUS_OK;
        }

        idx = (idx + 1) % map->cap;
    }

    *e = NULL;
    return STATUS_NOT_FOUND;
}

void fhmap_free(struct fhmap *map){
    struct fhmap* m = (struct fhmap*)map;
    free(m->arr);
    free(m);
}
