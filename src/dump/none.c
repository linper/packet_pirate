
/**
 * @file none.c
 * @brief Implementation of empty dump interface
 * @author Linas Perkauskas
 * @date 2022-03-31
 */

#include <stdlib.h>
#include <stdio.h>

#include "../../include/dump.h"

static status_val open()
{
	return STATUS_OK;
}

static status_val build(struct ef_tree *root)
{
	(void)root;
	return STATUS_OK;
}

static status_val dump(struct glist *lst)
{
	(void)lst;
	return STATUS_OK;
}

static status_val close()
{
	return STATUS_OK;
}

struct dump_ctx dctx = {
	.open = open,
	.build = build,
	.dump = dump,
	.close = close,
};

