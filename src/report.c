/**
 * @file report.c
 * @brief Implementation of capture statgistics interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include <stdio.h>
#include <string.h>

#include "../include/report.h"
#include "../include/ext_filter.h"
#include "../include/ef_tree.h"

/**
 * @brief Creates indentation prefix
 * @node[in] *node		Exended filter tree node to make report from
 * @node[in, out] *usr	Pointer to buffer to modify
 * @return Void
 */
static void build_prefix(struct ef_tree *node, void *usr)
{
	if (!node->par || (node->flt && !node->flt->active)) {
		return;
	}

	size_t len = strlen((char *)usr);
	char *wrt_ptr = ((char *)usr) + len;
	sprintf(wrt_ptr, "%s",
			(node->next && node->next->flt->active) ? "│ " : "  ");
}

/**
 * @brief Prints statistics for one node
 * @node[in] *node	Exended filter tree node to make report from
 * @return Void
 */
static void report_one(struct ef_tree *node, void *usr)
{
	(void)usr;

	if (node->flt && !node->flt->active) {
		return;
	}

	char dent[64] = "";
	bool more_sib = false, more_chl = false;
	struct ef_tree *eft;

	eft = node;
	while ((eft = eft->next)) {
		if (eft->flt->active) {
			more_sib = true;
			break;
		}
	}

	if (node->chld) {
		eft = node->chld;
		do {
			if (eft->flt->active) {
				more_chl = true;
				break;
			}
		} while ((eft = eft->next));
	}

	ef_tree_root_to_leaf_foreach(pc.ef_root, node->par, build_prefix, dent);

	const char *interc = more_sib ? "├─" : "└─";
	const char *next_br = more_sib ? "│ " : "  ";
	const char *chld_br = more_chl ? "│ " : "  ";

	struct filter *f = node->flt->filter;
	struct report *r = &node->flt->rep;

	printf("%s%s%s:\n", dent, interc, f->packet_tag);
	printf("%s%s%sreceived: %ld\n", dent, next_br, chld_br, r->received);
	printf("%s%s%sskiped: %ld\n", dent, next_br, chld_br, r->skiped);
	printf("%s%s%sunconverted: %ld\n", dent, next_br, chld_br, r->unconverted);
	printf("%s%s%sunsplit: %ld\n", dent, next_br, chld_br, r->unsplit);
	printf("%s%s%sinvadidated: %ld\n", dent, next_br, chld_br, r->invalid);
	printf("%s%s%struncated: %ld\n", dent, next_br, chld_br, r->truncated);
	printf("%s%s%sparsed: %ld\n", dent, next_br, chld_br, r->parsed);
	printf("%s%s%s\n", dent, next_br, chld_br);
}

void report_all()
{
	ef_tree_foreach(pc.ef_root, true, report_one, NULL);

	//mabe add agregated report TODO
}

