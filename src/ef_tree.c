/**
 * @file ef_tree.c
 * @brief Implementation of extended filter tree data structure interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include "../include/filter.h"
#include "../include/fhmap.h"
#include "../include/ext_filter.h"
#include "../include/ef_tree.h"

struct ef_tree *ef_tree_base()
{
	struct ef_tree *root = calloc(1, sizeof(struct ef_tree));
	if (!root) {
		LOG(L_CRIT, STATUS_OMEM);
		return NULL;
	}

	return root;
}

struct ef_tree *ef_tree_new(struct ext_filter *f)
{
	struct ef_tree *root = calloc(1, sizeof(struct ef_tree));
	if (!root) {
		LOG(L_CRIT, STATUS_OMEM);
		ext_filter_free(f);
		return NULL;
	}

	root->flt = f;

	return root;
}

status_val ef_tree_put(struct ef_tree *root, struct ext_filter *e)
{
	status_val ret;

	if ((!root->flt && !*e->filter->parent_tag) ||
		(root->flt &&

		 //checking is this correct parent node
		 !strcmp(root->flt->filter->packet_tag, e->filter->parent_tag))) {
		struct ef_tree *ef = ef_tree_new(e);
		if (!ef) {
			LOG(L_CRIT, STATUS_OMEM);
			return STATUS_OMEM;
		}

		ef->lvl = root->lvl + 1;
		ef->par = root;
		ef->next = root->chld; //adding to children linked list head
		root->chld = ef;

		return STATUS_OK;
	}

	if (root->chld) { //desending into child node, if it exists
		if (!(ret = ef_tree_put(root->chld, e))) {
			return ret; //returning back to beginning
		}
	}

	struct ef_tree *cur = root;

	while (cur->next) { //iterating over siblings
		if (!(ret = ef_tree_put(cur->next, e))) {
			return ret; //returning back to beginning
		}
		cur = cur->next;
	}

	LOG(L_WARN, STATUS_NOT_FOUND);
	return STATUS_NOT_FOUND;
}

status_val ef_tree_get(struct ef_tree *root, const char *tag,
					   struct ext_filter **e)
{
	status_val ret;

	//checking if current node is correct one
	if (!root->flt && !strcmp(tag, root->flt->filter->packet_tag)) {
		*e = root->flt;
		return STATUS_OK;
	}

	if (root->chld) {
		if (!(ret = ef_tree_get(root->chld, tag, e))) {
			return ret; //returning back to beginning
		}
	}

	struct ef_tree *cur = root;

	while (cur) {
		if (!(ret = ef_tree_get(cur->next, tag, e))) {
			return ret; //returning back to beginning
		}
		cur = cur->next;
	}

	LOG(L_WARN, STATUS_NOT_FOUND);
	return STATUS_NOT_FOUND;
}

status_val ef_tree_contains_by_tag(struct ef_tree *root, const char *tag)
{
	if (!root) {
		LOG(L_WARN, STATUS_NOT_FOUND);
		return STATUS_NOT_FOUND;
	}

	status_val ret;

	//checking if current node is correct one
	if (root->flt && !strcmp(tag, root->flt->filter->packet_tag)) {
		return STATUS_OK;
	}

	if (root->chld) {
		if (!(ret = ef_tree_contains_by_tag(root->chld, tag))) {
			return ret; //returning back to beginning
		}
	}

	if (root->next) {
		if (!(ret = ef_tree_contains_by_tag(root->next, tag))) {
			return ret; //returning back to beginning
		}
	}

	/*LOG(L_INFO, STATUS_NOT_FOUND);*/
	return STATUS_NOT_FOUND;
}

status_val ef_tree_get_entry(struct ef_tree *node, const char *tag,
							 struct f_entry **e)
{
	while (node) {
		if (!fhmap_get(node->flt->mapped_filter, tag, e)) {
			return STATUS_OK;
		}

		node = node->par;
	}

	return STATUS_NOT_FOUND;
}

status_val ef_tree_root_to_leaf_foreach(struct ef_tree *root,
										struct ef_tree *node,
										void (*func)(struct ef_tree *, void *),
										void *usr)
{
	if (!node) {
		LOG(L_WARN, STATUS_NOT_FOUND);
		return STATUS_NOT_FOUND;
	}

	status_val status = STATUS_OK;

	if ((node->par && node->par != root &&
		 ef_tree_root_to_leaf_foreach(root, node->par, func, usr)) ||
		(!node->par && node->par != root)) {
		return STATUS_NOT_FOUND;
	}

	func(node, usr);

	return status;
}

void ef_tree_foreach(struct ef_tree *node, bool skip_first,
					 void (*func)(struct ef_tree *, void *), void *usr)
{
	if (!node) {
		LOG(L_WARN, STATUS_NOT_FOUND);
		return;
	}

	if (!skip_first) {
		func(node, usr);
	}

	if (node->chld) {
		ef_tree_foreach(node->chld, false, func, usr);
	}

	if (!skip_first && node->next) {
		ef_tree_foreach(node->next, false, func, usr);
	}
}

/**
 * @brief Internal function. Iterates tree herachicly. Think of it as iteration with base 
 * as root node, but iteration starts from give node. I.e. continuing iterating
 * from specified node
 * @param[in] *node 	Tree node node to start iterating from
 * @param[in] *func 	User function callback to call at each node
 * @param[in] *usr 		User pointer to pass to callback function
 * @return Void
 */
static void _ef_tree_foreach_continue(struct ef_tree *node,
									  void (*func)(struct ef_tree *, void *),
									  void *usr)
{
	if (!node) {
		LOG(L_WARN, STATUS_NOT_FOUND);
		return;
	}

	//reached root
	if (!node->lvl) {
		return;
	}

	func(node, usr);

	if (node->next) {
		ef_tree_foreach(node->next, true, func, usr);
	}

	/* always has parent if lvl is not 0 
	going hierarchicly up*/
	_ef_tree_foreach_continue(node->par, func, usr);
}

inline void ef_tree_foreach_continue(struct ef_tree *node,
									 void (*func)(struct ef_tree *, void *),
									 void *usr)
{
	ef_tree_foreach(node, true, func, usr);
	_ef_tree_foreach_continue(node, func, usr);
}

void ef_tree_free(struct ef_tree *root)
{
	if (!root) {
		return;
	}

	if (root->chld) {
		ef_tree_free(root->chld);
	}

	if (root->next) {
		ef_tree_free(root->next);
	}

	ext_filter_free(root->flt);
	free(root);

	return;
}

