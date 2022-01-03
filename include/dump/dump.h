#ifndef H_DUMP
#define H_DUMP

#include "../utils.h"

struct dump_ctx {
	status_val (*open)();
	status_val (*build)(struct ef_tree *);
	status_val (*dump)(struct glist *);
	status_val (*close)();
};

extern struct dump_ctx dctx;

#endif
