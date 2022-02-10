
#include <stdio.h>

#include "../include/report.h"
#include "../include/ext_filter.h"
#include "../include/ef_tree.h"

static void report_one(struct ef_tree *node, void *usr)
{
	(void)usr;

	struct filter *f = node->flt->filter;
	struct report *r = &node->flt->rep;

	printf("%s:\n", f->packet_tag);
	printf("\treceived: %ld\n", r->received);
	printf("\tskiped: %ld\n", r->skiped);
	printf("\tunconverted: %ld\n", r->unconverted);
	printf("\tunsplit: %ld\n", r->unsplit);
	printf("\tinvadidated: %ld\n", r->invalid);
	printf("\ttruncated: %ld\n", r->truncated);
	printf("\tparsed: %ld\n", r->parsed);
	printf("\n");
}

void report_all()
{
	ef_tree_foreach(pc.ef_root, true, report_one, NULL);

	//mabe add agregated report TODO
}

