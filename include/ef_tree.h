#ifndef EF_TREE_H
#define EF_TREE_H

#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "ext_filter.h"

struct ef_tree {
    struct ef_tree *par; 	//parent node
    struct ef_tree *chld; 	//first child node
    struct ef_tree *next; 	//sibling node
    struct ext_filter *flt; 	//data, filter for current packet
    size_t lvl; 		//filter level - packet layer
};

struct ef_tree *ef_tree_base();

struct ef_tree *ef_tree_new();

status_val ef_tree_put(struct ef_tree *root, struct ext_filter *e);

status_val ef_tree_get(struct ef_tree *root, const char *tag, struct ext_filter **e);

status_val ef_tree_contains_by_tag(struct ef_tree *root, const char *tag);

void ef_tree_free(struct ef_tree *root);

#endif
