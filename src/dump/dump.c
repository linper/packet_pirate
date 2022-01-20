
#include <stdlib.h>
#include <stdio.h>

#ifdef DUMP_TYPE_SQLITE3
#include "../../include/dump/sqlite3.h"
#endif

#ifdef DUMP_TYPE_MYSQL
#include "../../include/dump/mysql.h"
#endif

#ifdef DUMP_TYPE_PQ
#include "../../include/dump/pq.h"
#endif

#include "../../include/dump/dump.h"

struct dump_ctx dctx = {
#ifdef DUMP_TYPE_SQLITE3
	.open = dump_sqlite3_open,
	.build = dump_sqlite3_build,
	.dump = dump_sqlite3_dump,
	.close = dump_sqlite3_close,
#endif

#ifdef DUMP_TYPE_MYSQL
	.open = dump_mysql_open,
	.build = dump_mysql_build,
	.dump = dump_mysql_dump,
	.close = dump_mysql_close,
#endif

#ifdef DUMP_TYPE_PQ
	.open = dump_pq_open,
	.build = dump_pq_build,
	.dump = dump_pq_dump,
	.close = dump_pq_close,
#endif
};

