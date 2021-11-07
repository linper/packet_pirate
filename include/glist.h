#ifndef GLIST_H
#define GLIST_H

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stddef.h>

#include "utils.h"

struct glist {
    void **array;
    size_t count;
    size_t cap;
    size_t min_cap;
    float shrink_threshold;
    void (*free_cb)(void*);
    void (*clone_cb)(void**, void*);
};

struct glist *glist_new(int cap);
//creates shallow clone unless clone_cb is set
struct glist *glist_clone(struct glist *lst);
void glist_clear(struct glist *lst);
//just sets count to 0
void glist_clear_shallow(struct glist *lst);
void glist_free(struct glist *lst);
void glist_free_shallow(struct glist *lst);
//appends value at the end of list 
status_val glist_push(struct glist *lst, void *value);
//copies len bytes from value and appends it at the end of list 
status_val glist_push2(struct glist *lst, void *value, size_t len);
//inserts value at specified index 
status_val glist_pop(struct glist *lst, void **value_ptr);
status_val glist_get(struct glist *lst, int index, void **value);
status_val glist_get_idx(struct glist *lst, void *value, int *index);
void *glist_remove(struct glist *lst, int index);
//deletes and frees element at index
status_val glist_delete(struct glist *lst, int index);
//same as glist_delete but does not free element at index
//same as glist_remove but does not return element at index
status_val glist_forget(struct glist *lst, int index);
status_val glist_copy_to(struct glist *src, struct glist *dst);
size_t glist_count(struct glist *lst);
void **glist_get_array(struct glist *lst);
void glist_set_free_cb(struct glist *lst, void (*cb)(void*));
//sets callback for every element for glist_clone
//cb(void **<pointer to clone data pointer>, void *<source data pointer>)
void glist_set_clone_cb(struct glist *lst, void (*cb)(void**, void*));

#define glist_foreach(item, list) 			\
    for(int keep = 1, 					\
            count = 0, 					\
            size = list->count;  			\
        keep && count != size; 				\
        keep = !keep, count++) 				\
      for(item = (list->array) + count; keep; keep = !keep)

#endif
