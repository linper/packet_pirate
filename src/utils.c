/**
 * @file utils.c
 * @brief Implementations of various utilities. It is also intended 
 * to be used by end user
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#include "../include/utils.h"
#include "../include/glist.h"
#include "../include/filter.h"

/** @brief Internal loging level to type string map */
const char *prog_verb_str[] = {
	[L_CRIT] = "CRITICAL", [L_ERR] = "ERROR", [L_WARN] = "WARNING",
	[L_NOTICE] = "NOTICE", [L_INFO] = "INFO", [L_DEBUG] = "DEBUG",
};

/** @brief Internal map for default logging messages */
static struct { ///< 		Structure to describe messages
	bool err; ///< 			Is this an error
	const char *desc; ///< 	Message type description
	const char *msg; ///< 	Default message
} msg_map[] = {
	[STATUS_OK] = { .err = false, .desc = "OK", .msg = NULL },
	[STATUS_ERROR] = { .err = true, .desc = "ERROR", .msg = "Error occured" },
	[STATUS_OMEM] = { .err = true, .desc = "OMEM", .msg = "Out of memory" },
	[STATUS_NOT_FOUND] = { .err = true,
						   .desc = "NOT FOUND",
						   .msg = "Value not found" },
	[STATUS_FULL] = { .err = true, .desc = "FULL", .msg = "Container is full" },
	[STATUS_DB] = { .err = true, .desc = "DB FAIL", .msg = "Database failure" },
	[STATUS_BAD_INPUT] = { .err = true,
						   .desc = "BAD INPUT",
						   .msg = "Invalid input value" },
};

/** @brief Djb2 hashing once again */
static void hash(u_char *data, size_t len, u_long *hash)
{
	u_char c;
	for (size_t i = 0; i < len; ++i) {
		c = *(data + i);
		*hash = ((*hash << 5) + *hash) + c; /* *hash * 33 + c */
	}

	return;
}

u_long get_global_hash()
{
	u_long g_hash = 5381;
	struct filter *f;
	glist_foreach (void *e, pc.f_reg) {
		f = (struct filter *)e;
		hash((u_char *)f->packet_tag, DEVEL_TAG_LEN, &g_hash);
		hash((u_char *)f->parent_tag, DEVEL_TAG_LEN, &g_hash);

		hash((u_char *)f->entries, f->n_entries * sizeof(struct f_entry),
			 &g_hash);
	}

	return g_hash;
}

void log_msg(verb lvl, status_val status, const char *func, int line,
			 const char *format, ...)
{
	char loc[strlen(func) + strlen(prog_verb_str[lvl]) +
			 strlen(msg_map[status].desc) + 8];
	char msg[256] = { 0 };

	sprintf(loc, "%s:[%d]:%s:%s", func, line, prog_verb_str[lvl],
			msg_map[status].desc);

	if (format) {
		va_list vl;
		va_start(vl, format);
		vsprintf(msg, format, vl);
		va_end(vl);
	} else if (msg_map[status].msg) {
		sprintf(msg, "%s", msg_map[status].msg);
	}

	fprintf(msg_map[status].err ? stderr : stdout, "%s: %s\n", loc, msg);

	return;
}
