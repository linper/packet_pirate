/**
 * @file pq.h
 * @brief Description of postgresql implementation of dump interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef H_DUMP_PQ
#define H_DUMP_PQ

#include "../utils.h"

status_val dump_pq_open();
status_val dump_pq_build(struct ef_tree *root);
status_val dump_pq_dump(struct glist *lst);
status_val dump_pq_close();

#endif

