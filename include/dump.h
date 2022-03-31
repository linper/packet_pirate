/**
 * @file dump.h
 * @brief Description of dump interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef H_DUMP
#define H_DUMP

#include "utils.h"

/** @brief Max blob fields count in filter */
#define PEBA_CAP 128

/** @brief Sump interface. Simmilar to interface class in OOP */
struct dump_ctx {
	status_val (*open)(); ///< 				DB open function callbacck
	status_val (*build)(
		struct ef_tree *); ///< 			DB build tables function callback
	status_val (*dump)(
		struct glist *); ///< 				DB dump data function callback
	status_val (*close)(); ///< 			DB close function callback
};

/** @brief Global database context instance */
extern struct dump_ctx dctx;

#endif
