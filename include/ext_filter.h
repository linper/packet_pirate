#ifndef EXT_FILTER_H
#define EXT_FILTER_H

#include <stdio.h>
#include <stdlib.h>

struct ext_filter {
	struct filter *filter; //user defined filter
	struct fhmap *mapped_filter; //tag=>entry mapped user defined filter
};

/**
 * @brief Cretes new extended filter with filter
 * @param f filter to put into extended filter
 * @return new extended filter if succeded, NULL otherwise
 */
struct ext_filter *ext_filter_new(struct filter *f);

/**
 * @brief Frees given extended filter
 * @param f exttended filter to free
 * @return Void
 */
void ext_filter_free(struct ext_filter *f);

#endif
