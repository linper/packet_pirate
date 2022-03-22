/**
 * @file mysql.c
 * @brief Implementation of mysql of dump interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <mysql/mysql.h>

#include "../../include/glist.h"
#include "../../include/ef_tree.h"
#include "../../include/ext_filter.h"
#include "../../include/filter.h"
#include "../../include/dump/dump.h"
#include "../../include/dump/mysql.h"

static MYSQL *db;

static status_val compare_db()
{
	long new_hash = (long)get_global_hash();
	long old_hash = 0;

	if (mysql_query(db, "SELECT * FROM context")) {
		return STATUS_DB;
	}

	MYSQL_RES *result = mysql_store_result(db);

	if (result == NULL) {
		return STATUS_DB;
	}

	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		old_hash = atol(row[0]);
	}

	mysql_free_result(result);

	if (new_hash != old_hash) {
		return STATUS_DB;
	}

	return STATUS_OK;
}

static status_val get_new_db_name(char *comp_name, char *res_name, bool *exists)
{
	if (mysql_query(db, "show databases")) {
		LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
		return STATUS_DB;
	}

	MYSQL_RES *result = mysql_store_result(db);

	if (result == NULL) {
		LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
		return STATUS_DB;
	}

	MYSQL_ROW row;
	int db_idx = 0;
	*exists = false;

	sprintf(res_name, "%s", comp_name);

	while ((row = mysql_fetch_row(result))) {
		if (row[0] && !strcmp(row[0], res_name)) {
			*exists = true;
			sprintf(res_name, "%s_%d", comp_name, ++db_idx);
		}
	}

	if (db_idx) {
		sprintf(res_name, "%s_%d", comp_name, db_idx);
	} else {
		sprintf(res_name, "%s", comp_name);
	}

	mysql_free_result(result);

	return STATUS_OK;
}

static void sync_db_context()
{
	char buff[DEVEL_BUF_SIZE];
	sprintf(buff, "UPDATE context SET pp_hash = %ld, next_idx = %ld;",
			pc.pp_hash, pc.next_pid);
	if (mysql_query(db, buff)) {
		LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
	}
}

static status_val create_or_sync_prog_context(char *buff)
{
	status_val status;

	status = compare_db();
	long pp_hash = (long)get_global_hash();

	if (status) { //database does not exist or is different
		if (mysql_query(db, "DROP TABLE IF EXISTS context")) {
			LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
			return STATUS_DB;
		}

		if (mysql_query(db,
						"CREATE TABLE context(pp_hash BIGINT, next_idx INT)")) {
			LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
			return STATUS_DB;
		}

		sprintf(buff, "INSERT INTO context VALUES(%ld, 0)", pp_hash);

		if (mysql_query(db, buff)) {
			LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
			return STATUS_DB;
		}

		pc.pp_hash = pp_hash;
		pc.next_pid = 0;
	} else { //database exists and is identical
		if (mysql_query(db, "SELECT pp_hash, next_idx FROM context")) {
			LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
			return STATUS_DB;
		}

		MYSQL_RES *result = mysql_store_result(db);

		if (result == NULL) {
			return STATUS_DB;
		}

		MYSQL_ROW row;

		while ((row = mysql_fetch_row(result))) {
			pc.pp_hash = atol(row[0]);
			pc.next_pid = atol(row[1]);
		}

		mysql_free_result(result);
	}

	return STATUS_OK;
}

static status_val build_table(struct ef_tree *root, char *buff)
{
	status_val status = STATUS_DB;

	if (!root->flt || !root->flt->active) {
		goto sibling;
	}

	int off = sprintf(buff, "CREATE TABLE IF NOT EXISTS %s(",
					  root->flt->filter->packet_tag);
	struct filter *f = root->flt->filter;

	off += sprintf(buff + off, "id INT PRIMARY KEY NOT NULL");
	off += sprintf(buff + off, ", tmst DATETIME NOT NULL");

	for (size_t i = 0; i < f->n_entries; i++) {
		const char *mand = f->entries[i].flags & EF_OPT ? "" : " NOT NULL";

		if (f->entries[i].flags & EF_NOWRT) {
			continue;
		}

		switch (wfc_arr[f->entries[i].write_form]) {
		case EWFC_INT:
			off +=
				sprintf(buff + off, ", %s BIGINT%s", f->entries[i].tag, mand);
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

	if (mysql_query(db, buff)) {
		LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
		return STATUS_DB;
	}

	//desending down into first child filter if it exists
	if (root->chld && (status = build_table(root->chld, buff))) {
		goto end;
	}

sibling:
	// going to sibling filter
	if (root->next && (status = build_table(root->next, buff))) {
		goto end;
	}

	status = STATUS_OK;
end:
	return status;
}

status_val dump_mysql_open()
{
	status_val status = STATUS_DB;
	char buff[DEVEL_BUF_SIZE] = { 0 };

	db = mysql_init(NULL);

	if (!db) {
		LOGF(L_CRIT, STATUS_DB, "%s", mysql_error(db));
		return STATUS_DB;
	}

	if (mysql_real_connect(db, DUMP_MYSQL_HOST, DUMP_MYSQL_USER,
						   DUMP_MYSQL_PASS, NULL, DUMP_MYSQL_PORT, NULL,
						   0) == NULL) {
		LOGF(L_CRIT, STATUS_DB, "%s", mysql_error(db));
		goto end;
	}

	char db_name_buff[DEVEL_BUF_SIZE] = { 0 };
	char *db_name = db_name_buff;
	bool exists = false;

	status = get_new_db_name(DUMP_MYSQL_DB, db_name, &exists);
	if (status) {
		LOG(L_CRIT, STATUS_DB);
		goto end;
	}

#ifdef DUMP_APPEND
	if (exists) {
		sprintf(buff, "USE %s", DUMP_MYSQL_DB);
		if (mysql_query(db, buff)) {
			LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
			goto end;
		}

		if (!compare_db()) {
			status = STATUS_OK;
			goto end;
		}
	}
#endif

#ifdef DUMP_OVERRIDE
	if (exists) {
		sprintf(buff, "DROP DATABASE %s", DUMP_MYSQL_DB);
		if (mysql_query(db, buff)) {
			LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
			goto end;
		}
	}

	sprintf(buff, "CREATE DATABASE %s", DUMP_MYSQL_DB);
	if (mysql_query(db, buff)) {
		LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
		goto end;
	}
	sprintf(buff, "USE %s", DUMP_MYSQL_DB);
	if (mysql_query(db, buff)) {
		LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
		goto end;
	}
#else
	sprintf(buff, "CREATE DATABASE %s", db_name);
	if (mysql_query(db, buff)) {
		LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
		goto end;
	}

	sprintf(buff, "USE %s", db_name);
	if (mysql_query(db, buff)) {
		LOGF(L_ERR, STATUS_DB, "%s", mysql_error(db));
		goto end;
	}
#endif
	status = STATUS_OK;
end:
	if (status) {
		mysql_close(db);
	}

	return status;
}

status_val dump_mysql_build(struct ef_tree *root)
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
		status = STATUS_OK;
		goto end;
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

status_val dump_mysql_dump(struct glist *lst)
{
	struct p_entry *pe_blob_arr[PEBA_CAP] = { 0 };
	u_int peba_len = 0;
	status_val status = STATUS_DB;
	MYSQL_STMT *stmt = NULL;

	char *buff = malloc(8 * DEVEL_BUF_SIZE);
	if (!buff) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	stmt = mysql_stmt_init(db);
	if (!stmt) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	struct packet *p;
	glist_foreach (void *e, lst) {
		peba_len = 0;
		p = (struct packet *)e;

		int off = sprintf(buff, "INSERT INTO %s VALUES(", p->packet_tag);

		off += sprintf(buff + off, "%d, now()", p->id);

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

		if (mysql_stmt_prepare(stmt, buff, strlen(buff))) {
			LOGF(L_ERR, STATUS_DB, "%s", mysql_stmt_error(stmt));
			goto end;
		}

		MYSQL_BIND bind[peba_len];

		memset(bind, 0, sizeof(bind));

		for (size_t i = 0; i < peba_len; i++) {
			bind[i].buffer_type = MYSQL_TYPE_BLOB;
			bind[i].length = &pe_blob_arr[i]->conv_data.blob.len;
			bind[i].is_null = 0;
		}

		if (mysql_stmt_bind_param(stmt, bind)) {
			LOGF(L_ERR, STATUS_DB, "%s", mysql_stmt_error(stmt));
			goto end;
		}

		for (size_t i = 0; i < peba_len; i++) {
			if (mysql_stmt_send_long_data(
					stmt, i, (const char *)pe_blob_arr[i]->conv_data.blob.arr,
					pe_blob_arr[i]->conv_data.blob.len)) {
				status = STATUS_DB;
				LOGF(L_ERR, status, "%s", mysql_stmt_error(stmt));
				goto end;
			}
		}

		if (mysql_stmt_execute(stmt)) {
			status = STATUS_DB;
			LOGF(L_ERR, status, "%s", mysql_stmt_error(stmt));
			goto end;
		}
	}

	status = STATUS_OK;

end:
	mysql_stmt_close(stmt);
	free(buff);
	return status;
}

status_val dump_mysql_close()
{
	dump_mysql_dump(pc.cap_pkts); //syncing unwritten data
	sync_db_context();
	mysql_close(db);
	mysql_library_end();
	return STATUS_OK;
}

