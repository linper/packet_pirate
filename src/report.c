
#include <stdio.h>
#include <string.h>

#include "../include/report.h"
#include "../include/ext_filter.h"
#include "../include/ef_tree.h"

static void build_prefix(struct ef_tree *node, void *usr)
{
	if (!node->par) {
		return;
	}

	size_t len = strlen((char *)usr);
	char *wrt_ptr = ((char *)usr) + len;
	sprintf(wrt_ptr, "%s", node->next ? "│ " : "  ");
}

static void report_one(struct ef_tree *node, void *usr)
{
	(void)usr;

	char dent[64] = "";

	ef_tree_root_to_leaf_foreach(pc.ef_root, node->par, build_prefix, dent);

	const char *interc = node->next ? "├─" : "└─";
	const char *next_br = node->next ? "│ " : "  ";
	const char *chld_br = node->chld ? "│ " : "  ";

	struct filter *f = node->flt->filter;
	struct report *r = &node->flt->rep;

	printf("%s%s%s:\n", dent, interc, f->packet_tag);
	printf("%s%s%sreceived: %ld\n", dent, next_br, chld_br, r->received);
	printf("%s%s%sskiped: %ld\n", dent, next_br, chld_br, r->skiped);
	printf("%s%s%sunconverted: %ld\n", dent, next_br, chld_br, r->unconverted);
	printf("%s%s%sunsplit: %ld\n", dent, next_br, chld_br, r->unsplit);
	printf("%s%s%snvadidated: %ld\n", dent, next_br, chld_br, r->invalid);
	printf("%s%s%struncated: %ld\n", dent, next_br, chld_br, r->truncated);
	printf("%s%s%sparsed: %ld\n", dent, next_br, chld_br, r->parsed);
	printf("%s%s%s\n", dent, next_br, chld_br);
}

void report_all()
{
	ef_tree_foreach(pc.ef_root, true, report_one, NULL);

	//mabe add agregated report TODO
}

