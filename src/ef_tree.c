#include "../include/ef_tree.h"

struct ef_tree *ef_tree_base()
{
	struct ext_filter *f = ext_filter_base();
	if (!f) {
		LOG(L_CRIT, STATUS_OMEM);
		return NULL;
	}

	struct ef_tree *root = calloc(1, sizeof(struct ef_tree));
	if (!root) {
		LOG(L_CRIT, STATUS_OMEM);
		ext_filter_free(f);
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

	while (cur) { //iterating over siblings
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

	struct ef_tree *cur = root->next;

	while (cur) {
		if (!(ret = ef_tree_contains_by_tag(cur->next, tag))) {
			return ret; //returning back to beginning
		}
		cur = cur->next;
	}

	LOG(L_WARN, STATUS_NOT_FOUND);
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

void ef_tree_free(struct ef_tree *root)
{
	if (root->chld) {
		ef_tree_free(root->chld);
	}

	struct ef_tree *cur = root;
	struct ef_tree *next = NULL;

	while (cur) {
		//cur will be freed in next step, so I have to get next node now
		next = cur->next;
		ef_tree_free(cur);
		cur = next;
	}

	ext_filter_free(root->flt);
	free(root);

	return;
}

