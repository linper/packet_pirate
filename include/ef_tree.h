#ifndef EF_TREE_H
#define EF_TREE_H

#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include "utils.h"
#include "filter.h"

struct ef_tree {
	struct ef_tree *par; //parent node
	struct ef_tree *chld; //first child node
	struct ef_tree *next; //sibling node
	struct ext_filter *flt; //data, filter for current packet
	u_char lvl; //filter level - packet layer
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
status_val ef_tree_get(struct ef_tree *root, const char *tag,
					   struct ext_filter **e);

/**
 * @brief Checks if tree contains filter identified by given tag
 * @param root Tree root node
 * @param tag Value to compare too
 * @return STATUS_OK if succeded
 */
status_val ef_tree_contains_by_tag(struct ef_tree *root, const char *tag);

/**
 * @brief Gets entry field indicated by tag while propagating upwards to root
 * @param node Tree node node to start search from
 * @param tag Entry tag value to compare too
 * @return STATUS_OK if succeded, STATUS_NOT_FOUND otherwise
 */
status_val ef_tree_get_entry(struct ef_tree *node, const char *tag,
							 struct f_entry **e);

/**
 * @brief Iterates tree from specified root to leaf node instraight path
 * @param root Tree node node to start iterating from
 * @param node Tree node node to end iterating at
 * @param func user function callback to call at each node
 * @param usr user pointer to pass to callback function
 * @returns if root node is reachable - STATUS_OK, STATUS_NOT_FOUND - otherwise
 */
status_val ef_tree_root_to_leaf_foreach(struct ef_tree *root,
										struct ef_tree *node,
										void (*func)(struct ef_tree *, void *),
										void *usr);

/**
 * @brief Iterates tree herachicly down
 * @param node Tree node node to start iterating from
 * @param skip_fist wether to skip first node
 * @param func user function callback to call at each node
 * @param usr user pointer to pass to callback function
 */
void ef_tree_foreach(struct ef_tree *node, bool skip_first,
					 void (*func)(struct ef_tree *, void *), void *usr);

/**
 * @brief Iterates tree herachicly. Think of it as iteration with base 
 * as root node, but iteration starts from give node. I.e. continuing iterating
 * from specified node
 * @param node Tree node node to start iterating from
 * @param func user function callback to call at each node
 * @param usr user pointer to pass to callback function
 */
void ef_tree_foreach_continue(struct ef_tree *node,
							  void (*func)(struct ef_tree *, void *),
							  void *usr);

/**
 * @brief Frees whole tree structure including contained ext_filters
 * @param root Root node of exttended filter tree
 * @return Void
 */
void ef_tree_free(struct ef_tree *root);

#endif
