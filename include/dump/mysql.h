#ifndef H_DUMP_MYSQL
#define H_DUMP_MYSQL

#include "../utils.h"

status_val dump_mysql_open();
status_val dump_mysql_build(struct ef_tree *root);
status_val dump_mysql_dump(struct glist *lst);
status_val dump_mysql_close();

#endif

