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

/**
 * @brief Cretes new empty tree node
 * @return new node if succeded, NULL otherwise
 */
struct ef_tree *ef_tree_base();

/**
 * @brief Cretes new tree node with extended filter
 * @param f extended filter to put into node
 * @return new node if succeded, NULL otherwise
 */
struct ef_tree *ef_tree_new(struct ext_filter *f);

/**
 * @brief Sets extended filter into filter tree if possible
 * @param root Tree root node
 * @param e New extended filter
 * @return STATUS_OK if succeded
 */
status_val ef_tree_put(struct ef_tree *root, struct ext_filter *e);

/**
 * @brief Gets extended filter indicated by tag from filter tree
 * @param root Tree root node
 * @param tag Value to compare too
 * @param e Pointer to return walue
 * @return STATUS_OK if succeded
 */
status_val ef_tree_get(struct ef_tree *root, const char *tag, struct ext_filter **e);

/**
 * @brief Checks if tree contains filter identified by given tag
 * @param root Tree root node
 * @param tag Value to compare too
 * @return STATUS_OK if succeded
 */ 
status_val ef_tree_contains_by_tag(struct ef_tree *root, const char *tag);

/**
 * @brief Frees whole tree structure including contained ext_filters
 * @param root Root node of exttended filter tree
 * @return Void
 */
void ef_tree_free(struct ef_tree *root);

#endif
