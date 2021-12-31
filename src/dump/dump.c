
#include <stdlib.h>
#include <stdio.h>

#ifdef DUMP_TYPE_SQLITE3
#include <sqlite3.h>

#include "../../include/dump/sqlite3.h"
#endif

#include "../../include/dump/dump.h"


struct dump_ctx dctx = {
#ifdef DUMP_TYPE_SQLITE3
	.open = dump_sqlite3_open,
	.build = dump_sqlite3_build,
	.dump = dump_sqlite3_dump,
	.close = dump_sqlite3_close,
#endif
};

