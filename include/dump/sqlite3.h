#ifndef H_DUMP_SQLITE3
#define H_DUMP_SQLITE3

#include "../utils.h"

status_val dump_sqlite3_open();
status_val dump_sqlite3_build(struct ef_tree *root);
status_val dump_sqlite3_dump(struct glist *lst);
status_val dump_sqlite3_close();

#endif
