/**
 * @file ef_tree.h
 * @brief Description of extended filter tree data structure interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef EF_TREE_H
#define EF_TREE_H

#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include "utils.h"
#include "filter.h"

/** @brief Extended filter tree node struct */
struct ef_tree {
	struct ef_tree *par; ///< 		Parent node
	struct ef_tree *chld; ///< 		First child node
	struct ef_tree *next; ///< 		Sibling node
	struct ext_filter *flt; ///< 	Data, filter for current packet
	u_char lvl; ///< 				Filter/packet layer
};

/**
 * @brief Cretes new empty tree node
 * @return New node if succeded, NULL otherwise
 */
struct ef_tree *ef_tree_base();

/**
 * @brief Cretes new tree node with extended filter
 * @param[in] *f Extended filter to put into node
 * @return New node if succeded, NULL otherwise
 */
struct ef_tree *ef_tree_new(struct ext_filter *f);

/**
 * @brief Sets extended filter into filter tree if possible
 * @param[in] *root 	Tree root node
 * @param[in] *e 		New extended filter
 * @return STATUS_OK if succeded
 */
status_val ef_tree_put(struct ef_tree *root, struct ext_filter *e);

/**
 * @brief Gets extended filter indicated by tag from filter tree
 * @param[in] *root 	Tree root node
 * @param[in] *tag 		Value to compare too
 * @param[out] **e 		Pointer to return walue
 * @return STATUS_OK if succeded
 */
status_val ef_tree_get(struct ef_tree *root, const char *tag,
					   struct ext_filter **e);

/**
 * @brief Checks if tree contains filter identified by given tag
 * @param[in] *root 	Tree root node
 * @param[in] *tag 		Value to compare too
 * @return STATUS_OK if succeded
 */
status_val ef_tree_contains_by_tag(struct ef_tree *root, const char *tag);

/**
 * @brief Gets entry field indicated by tag while propagating upwards to root
 * @param[in] *node 	Tree node node to start search from
 * @param[in] *tag 		Entry tag value to compare too
 * @param[out] **e 		Pointer to return walue
 * @return STATUS_OK if succeded, STATUS_NOT_FOUND otherwise
 */
status_val ef_tree_get_entry(struct ef_tree *node, const char *tag,
							 struct f_entry **e);

/**
 * @brief Iterates tree from specified root to leaf node instraight path
 * @param[in] *root 	Tree node node to start iterating from
 * @param[in] *node 	Tree node node to end iterating at
 * @param[in] *func 	User function callback to call at each node
 * @param[in] *usr 		User pointer to pass to callback function
 * @returns If root node is reachable - STATUS_OK, STATUS_NOT_FOUND - otherwise
 */
status_val ef_tree_root_to_leaf_foreach(struct ef_tree *root,
										struct ef_tree *node,
										void (*func)(struct ef_tree *, void *),
										void *usr);

/**
 * @brief Iterates tree herachicly down
 * @param[in] *node 		Tree node node to start iterating from
 * @param[in] *skip_fist 	Whether to skip first node
 * @param[in] *func 		User function callback to call at each node
 * @param[in] *usr 			User pointer to pass to callback function
 * @return Void
 */
void ef_tree_foreach(struct ef_tree *node, bool skip_first,
					 void (*func)(struct ef_tree *, void *), void *usr);

/**
 * @brief Iterates tree herachicly. Think of it as iteration with base 
 * as root node, but iteration starts from give node. I.e. continuing iterating
 * from specified node
 * @param[in] *node 	Tree node node to start iterating from
 * @param[in] *func 	User function callback to call at each node
 * @param[in] *usr 		User pointer to pass to callback function
 * @return Void
 */
void ef_tree_foreach_continue(struct ef_tree *node,
							  void (*func)(struct ef_tree *, void *),
							  void *usr);

/**
 * @brief Frees whole tree structure including contained ext_filters
 * @param[in] *root Root node of exttended filter tree
 * @return Void
 */
void ef_tree_free(struct ef_tree *root);

#endif
