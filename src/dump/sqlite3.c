/**
 * @file sqlite3.c
 * @brief Implementation of sqlite3 of dump interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include <sqlite3.h>

#include "../../include/glist.h"
#include "../../include/ef_tree.h"
#include "../../include/ext_filter.h"
#include "../../include/filter.h"
#include "../../include/dump.h"

static status_val dump_sqlite3_close();

static struct sqlite3 *db;

static status_val compare_db()
{
	long new_hash = (long)get_global_hash();
	long old_hash = 0;
	sqlite3_stmt *stmt;
	const char *sql = "SELECT pp_hash FROM context";
	int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		return STATUS_DB;
	}

	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		old_hash = (long)sqlite3_column_int64(stmt, 0);
	}

	if (rc != SQLITE_DONE) {
		return STATUS_DB;
	}

	sqlite3_finalize(stmt);

	if (new_hash != old_hash) {
		return STATUS_DB;
	}

	return STATUS_OK;
}

static void sync_db_context()
{
	char buff[DEVEL_BUF_SIZE];
	sprintf(buff, "UPDATE context SET pp_hash = %ld, next_idx = %ld;",
			pc.pp_hash, pc.next_pid);
	if (sqlite3_exec(db, buff, 0, 0, NULL) != SQLITE_OK) {
		LOGF(L_ERR, STATUS_DB, "%s", sqlite3_errmsg(db));
	}
}

static status_val create_or_sync_prog_context(char *buff)
{
	int rc;
	status_val status;

	status = compare_db();
	long pp_hash = (long)get_global_hash();

	if (status) { //database does not exist or is different
		sprintf(buff, "DROP TABLE IF EXISTS context;\
			CREATE TABLE context(pp_hash INT, next_idx INT);\
			INSERT INTO context VALUES(%ld, 0);",
				pp_hash);

		rc = sqlite3_exec(db, buff, 0, 0, NULL);
		if (rc != SQLITE_OK) {
			LOGF(L_ERR, STATUS_DB, "%s", sqlite3_errmsg(db));
			return STATUS_DB;
		}

		pc.pp_hash = pp_hash;
		pc.next_pid = 0;
	} else { //database exists and is identical
		sqlite3_stmt *stmt;
		rc = sqlite3_prepare_v2(db, "SELECT pp_hash, next_idx FROM context", -1,
								&stmt, NULL);
		if (rc != SQLITE_OK) {
			return STATUS_DB;
		}

		while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
			pc.pp_hash = (u_long)sqlite3_column_int64(stmt, 0);
			pc.next_pid = (size_t)sqlite3_column_int64(stmt, 1);
		}

		if (rc != SQLITE_DONE) {
			return STATUS_DB;
		}

		sqlite3_finalize(stmt);
	}
	return STATUS_OK;
}

static status_val build_table(struct ef_tree *root, char *buff)
{
	int rc;
	status_val status = STATUS_DB;

	if (!root->flt || !root->flt->active) {
		goto sibling;
	}

	int off = sprintf(buff, "CREATE TABLE IF NOT EXISTS %s(",
					  root->flt->filter->packet_tag);
	struct filter *f = root->flt->filter;

	off += sprintf(buff + off, "id INT PRIMARY KEY NOT NULL");
	off += sprintf(buff + off, ", tmst TEXT NOT NULL");

	for (size_t i = 0; i < f->n_entries; i++) {
		const char *mand = f->entries[i].flags & EF_OPT ? "" : " NOT NULL";

		if (f->entries[i].flags & EF_NOWRT) {
			continue;
		}

		switch (wfc_arr[f->entries[i].write_form]) {
		case EWFC_INT:
			off += sprintf(buff + off, ", %s INT%s", f->entries[i].tag, mand);
			break;
		case EWFC_STR:
			off += sprintf(buff + off, ", %s TEXT%s", f->entries[i].tag, mand);
			break;
		case EWFC_BLOB:
			off += sprintf(buff + off, ", %s BLOB%s", f->entries[i].tag, mand);
			break;
		default:
			break;
		}
	}

	if (f->parent_tag[0]) {
		off += sprintf(buff + off, ", parent_id INT");
		off += sprintf(buff + off, ", FOREIGN KEY(parent_id) REFERENCES %s(id)",
					   f->parent_tag);
	}

	off += sprintf(buff + off, ");");

	if ((rc = sqlite3_exec(db, buff, 0, 0, NULL)) != SQLITE_OK) {
		LOGF(L_CRIT, STATUS_DB, "%s", sqlite3_errmsg(db));
		return STATUS_DB;
	}

	//desending down into first child filter if it exists
	if (root->chld && build_table(root->chld, buff)) {
		goto end;
	}

sibling:
	// going to sibling filter
	if (root->next && build_table(root->next, buff)) {
		goto end;
	}

	status = STATUS_OK;
end:
	return status;
}

static status_val dump_sqlite3_open()
{
	int rc;
	char path[DEVEL_BUF_SIZE] = { 0 };
	bool exists = false;

	sprintf(path, "%s/%s.db", DUMP_SQLITE3_PATH, DUMP_SQLITE3_DB);

	if (!access(path, F_OK)) {
		exists = true;
	}

#ifdef DUMP_APPEND
	if (exists) {
		if ((rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, "unix")) !=
			SQLITE_OK) {
			LOGF(L_CRIT, STATUS_DB, "%s:%d", sqlite3_errmsg(db), rc);
			return STATUS_DB;
		}

		if (compare_db()) {
			dump_sqlite3_close();
		} else {
			return STATUS_OK;
		}
	}
#endif

#ifdef DUMP_OVERRIDE
	if (exists && remove(path)) {
		LOGF(L_CRIT, STATUS_DB, "Unable to delete: %s", path);
		return STATUS_DB;
	}

	if ((rc = sqlite3_open_v2(path, &db,
							  SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
							  "unix")) != SQLITE_OK) {
		LOGF(L_CRIT, STATUS_DB, "%s:%d", sqlite3_errmsg(db), rc);
		return STATUS_DB;
	}

	return STATUS_OK;
#else
	if (!exists) {
		if ((rc = sqlite3_open_v2(path, &db,
								  SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
								  "unix")) != SQLITE_OK) {
			LOGF(L_CRIT, STATUS_DB, "%s:%d", sqlite3_errmsg(db), rc);
			return STATUS_DB;
		} else {
			return STATUS_OK;
		}
	}

	size_t counter = 1;
	while (exists) {
		sprintf(path, "%s/%s_%ld.db", DUMP_SQLITE3_PATH, DUMP_SQLITE3_DB,
				counter++);

		if (access(path, F_OK)) {
			exists = false;
		}
	}

	if ((rc = sqlite3_open_v2(path, &db,
							  SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
							  "unix")) != SQLITE_OK) {
		LOGF(L_CRIT, STATUS_DB, "%s:%d", sqlite3_errmsg(db), rc);
		return STATUS_DB;
	}
	return STATUS_OK;
#endif
}

static status_val dump_sqlite3_build(struct ef_tree *root)
{
	status_val status = STATUS_DB;
	bool ident = false;

	if (!compare_db()) {
		ident = true;
	}

	char *buff = malloc(8 * DEVEL_BUF_SIZE);
	if (!buff) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	status = create_or_sync_prog_context(buff);
	if (status) {
		LOG(L_CRIT, status);
		goto end;
	}

	if (ident) { //skipping if identical database already exists
		free(buff);
		return STATUS_OK;
	}

	//desending down into first child filter if it exists
	if (root->chld && (status = build_table(root->chld, buff))) {
		goto end;
	}

	status = STATUS_OK;

end:
	free(buff);
	return status;
}

static status_val dump_sqlite3_dump(struct glist *lst)
{
	int rc;
	struct p_entry *pe_blob_arr[PEBA_CAP] = { 0 };
	u_int peba_len = 0;
	status_val status = STATUS_DB;

	char *buff = malloc(8 * DEVEL_BUF_SIZE);
	if (!buff) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	struct packet *p;
	glist_foreach (void *e, lst) {
		peba_len = 0;
		p = (struct packet *)e;

		int off = sprintf(buff, "INSERT INTO %s VALUES(", p->packet_tag);

		off += sprintf(buff + off, "%d, datetime('now')", p->id);

		for (long i = 0; i < p->e_len; i++) {
			switch (p->entries[i].wfc) {
			case EWFC_INT:
				off +=
					sprintf(buff + off, ", %ld", p->entries[i].conv_data.ulong);
				break;
			case EWFC_STR:
				off += sprintf(buff + off, ", \'%s\'",
							   p->entries[i].conv_data.string);
				break;
			case EWFC_BLOB:
				if (peba_len + 1 == PEBA_CAP) {
					LOGM(L_ERR, STATUS_BAD_INPUT,
						 "Too many replaceable parameters(BLOB)");
					goto end;
				}

				off += sprintf(buff + off, ", ?");
				pe_blob_arr[peba_len] = &p->entries[i];
				peba_len++;
				break;
			case EWFC_REAL:
				off +=
					sprintf(buff + off, ", %lf", p->entries[i].conv_data.real);
				break;
			default:
				break;
			}
		}

		if (p->parent_tag[0]) {
			off += sprintf(buff + off, ", %d", p->id);
		}

		off += sprintf(buff + off, ");");

		sqlite3_stmt *stmt;
		if ((rc = sqlite3_prepare_v2(db, buff, -1, &stmt, NULL)) != SQLITE_OK) {
			LOGF(L_ERR, STATUS_DB, "%s", sqlite3_errmsg(db));
			goto end;
		}

		for (size_t i = 0; i < peba_len; i++) {
			rc = sqlite3_bind_blob(stmt, i + 1,
								   pe_blob_arr[i]->conv_data.blob.arr,
								   pe_blob_arr[i]->conv_data.blob.len,
								   SQLITE_STATIC);
			if (rc != SQLITE_OK) {
				LOGF(L_ERR, STATUS_DB, "%s", sqlite3_errmsg(db));
			}
		}

		while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
			;

		sqlite3_finalize(stmt);
	}

	status = STATUS_OK;

end:
	free(buff);
	return status;
}

static status_val dump_sqlite3_close()
{
	dump_sqlite3_dump(pc.single_cap_pkt); //syncing unwritten data
	sync_db_context();
	sqlite3_close_v2(db);
	return STATUS_OK;
}

struct dump_ctx dctx = {
	.open = dump_sqlite3_open,
	.build = dump_sqlite3_build,
	.dump = dump_sqlite3_dump,
	.close = dump_sqlite3_close,
};

