/**
 * @file ext_filter.h
 * @brief Description of extended filter interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef EXT_FILTER_H
#define EXT_FILTER_H

#include <stdio.h>
#include <stdlib.h>
#include "report.h"

/**
 * @brief Struct to hold not user definable data about user defind filter
 */
struct ext_filter {
	bool active; ///< 					Is this filter active/enbled
	struct filter *filter; ///< 		User defined filter
	struct fhmap *mapped_filter; ///< 	Tag=>entry mapped user defined filter
	struct report rep; ///< 			Session capture statistics
	const char *hint; ///< 				Hinting next filter, must be cleared before each capaure
};

/**
 * @brief Cretes new extended filter with filter
 * @param[in] *f Filter to put into extended filter
 * @return New extended filter if succeded, NULL otherwise
 */
struct ext_filter *ext_filter_new(struct filter *f);

/**
 * @brief Frees given extended filter
 * @param[in] *f Extended filter to free
 * @return Void
 */
void ext_filter_free(struct ext_filter *f);

#endif
