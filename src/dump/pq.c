/**
 * @file pq.c
 * @brief Implementation of postgresql of dump interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <libpq-fe.h>

#include "../../include/glist.h"
#include "../../include/ef_tree.h"
#include "../../include/ext_filter.h"
#include "../../include/filter.h"
#include "../../include/dump/dump.h"
#include "../../include/dump/pq.h"

PGconn *db = NULL;

static status_val compare_db()
{
	long new_hash = (long)get_global_hash();
	long old_hash = 0;
	PGresult *res;

	res = PQexec(db, "SELECT * FROM context");
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		PQclear(res);
		return STATUS_DB;
	}

	int rows = PQntuples(res);
	char *entry = NULL;

	int db_idx = 0;
	for (int i = 0; i < rows; i++) {
		entry = PQgetvalue(res, db_idx, 0);
		old_hash = atol(entry);
	}

	PQclear(res);

	if (new_hash != old_hash) {
		return STATUS_DB;
	}

	return STATUS_OK;
}

static status_val get_new_db_name(char *comp_name, char *res_name, bool *exists)
{
	PGresult *res =
		PQexec(db, "SELECT datname FROM pg_database order by datname");
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		LOGF(L_ERR, STATUS_DB, "%s", "No data retrieved");
		PQclear(res);
		return STATUS_DB;
	}

	int rows = PQntuples(res);
	char *entry = NULL;
	int db_idx = 0;
	int row_idx = 0;

	sprintf(res_name, "%s", comp_name);

	while (row_idx < rows) {
		entry = PQgetvalue(res, row_idx++, 0);
		if (entry && !strcmp(entry, res_name)) {
			*exists = true;
			sprintf(res_name, "%s_%d", comp_name, ++db_idx);
		}
	}

	if (!db_idx) {
		sprintf(res_name, "%s", comp_name);
	}

	PQclear(res);

	return STATUS_OK;
}

static void sync_db_context()
{
	if (!db) {
		return;
	}

	char buff[DEVEL_BUF_SIZE];
	sprintf(buff, "UPDATE context SET pp_hash = %ld, next_idx = %ld;",
			pc.pp_hash, pc.next_pid);

	PGresult *res = PQexec(db, buff);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		LOGF(L_ERR, STATUS_DB, "%s", "No data retrieved");
	}

	PQclear(res);
}

static status_val create_or_sync_prog_context(char *buff)
{
	status_val status;

	status = compare_db();
	long pp_hash = (long)get_global_hash();
	PGresult *res;

	if (status) { //database does not exist or is different
		res = PQexec(db, "DROP TABLE IF EXISTS context");
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			LOGF(L_ERR, STATUS_DB, "%s", PQerrorMessage(db));
			status = STATUS_DB;
			goto end;
		}

		res = PQexec(db, "CREATE TABLE context(pp_hash BIGINT, next_idx INT)");
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			LOGF(L_ERR, STATUS_DB, "%s", PQerrorMessage(db));
			status = STATUS_DB;
			goto end;
		}

		sprintf(buff, "INSERT INTO context VALUES(%ld, 0)", pp_hash);

		res = PQexec(db, buff);
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			LOGF(L_ERR, STATUS_DB, "%s", PQerrorMessage(db));
			status = STATUS_DB;
			goto end;
		}

		pc.pp_hash = pp_hash;
		pc.next_pid = 0;
	} else { //database exists and is identical
		res = PQexec(db, "SELECT pp_hash, next_idx FROM context");
		if (PQresultStatus(res) != PGRES_TUPLES_OK) {
			LOGF(L_ERR, STATUS_DB, "%s", PQerrorMessage(db));
			status = STATUS_DB;
			goto end;
		}

		int rows = PQntuples(res);
		for (int i = 0; i < rows; ++i) {
			pc.pp_hash = atol(PQgetvalue(res, i, 0));
			pc.next_pid = atol(PQgetvalue(res, i, 1));
		}
	}

	status = STATUS_OK;
end:
	PQclear(res);
	return status;
}

status_val dump_pq_open()
{
	status_val status = STATUS_DB;
	char buff[DEVEL_BUF_SIZE] = { 0 };
	PGresult *res = NULL;

	sprintf(buff, "%d", DUMP_PQ_PORT);
	db = PQsetdbLogin(DUMP_PQ_HOST, buff, NULL, NULL, NULL, DUMP_PQ_USER,
					  DUMP_PQ_PASS);

	if (PQstatus(db) != CONNECTION_OK) {
		LOGF(L_CRIT, STATUS_DB, "Connection to database failed: %s\n",
			 PQerrorMessage(db));
		goto end;
	}

	char db_name_buff[DEVEL_BUF_SIZE] = { 0 };
	char *db_name = db_name_buff;
	bool exists = false;

	status = get_new_db_name(DUMP_PQ_DB, db_name, &exists);
	if (status) {
		LOG(L_CRIT, STATUS_DB);
		goto end;
	}

#ifdef DUMP_APPEND
	if (exists) {
		PQfinish(db);
		sprintf(buff, "%d", DUMP_PQ_PORT);
		db = PQsetdbLogin(DUMP_PQ_HOST, buff, NULL, NULL, DUMP_PQ_DB,
						  DUMP_PQ_USER, DUMP_PQ_PASS);

		if (PQstatus(db) != CONNECTION_OK) {
			LOGF(L_CRIT, STATUS_DB, "Connection to database failed: %s\n",
				 PQerrorMessage(db));
			goto end;
		}

		if (!compare_db()) {
			status = STATUS_OK; //nothing more to be done
			goto end;
		}
	}
#endif

#ifdef DUMP_OVERRIDE
	if (exists) {
		sprintf(buff, "%s", "DO $$ DECLARE \
			  r RECORD; \
			BEGIN \
			  FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = current_schema()) LOOP \
				EXECUTE 'DROP TABLE ' || quote_ident(r.tablename) || ' CASCADE'; \
			  END LOOP; \
			END $$;");
		res = PQexec(db, buff);
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			LOGF(L_ERR, STATUS_DB, "%s", PQerrorMessage(db));
			goto end;
		}
	}

	sprintf(db_name, "%s", DUMP_PQ_DB);
#else

	sprintf(buff, "CREATE DATABASE %s", db_name);
	res = PQexec(db, buff);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		LOGF(L_ERR, STATUS_DB, "%s", PQerrorMessage(db));
		goto end;
	}

	PQfinish(db);

	sprintf(buff, "%d", DUMP_PQ_PORT);
	db = PQsetdbLogin(DUMP_PQ_HOST, buff, NULL, NULL, db_name, DUMP_PQ_USER,
					  DUMP_PQ_PASS);

	if (PQstatus(db) != CONNECTION_OK) {
		LOGF(L_CRIT, STATUS_DB, "Connection to database failed: %s\n",
			 PQerrorMessage(db));
		goto end;
	}
#endif

	status = STATUS_OK;
end:
	if (status) {
		PQfinish(db);
	}

	if (res) {
		PQclear(res);
	}

	return status;
}

static status_val build_table(struct ef_tree *root, char *buff)
{
	status_val status = STATUS_DB;

	int off = sprintf(buff, "CREATE TABLE IF NOT EXISTS %s(",
					  root->flt->filter->packet_tag);
	struct filter *f = root->flt->filter;

	off += sprintf(buff + off, "id INT PRIMARY KEY NOT NULL");
	off += sprintf(buff + off, ", tmst TIMESTAMP NOT NULL");

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
			off += sprintf(buff + off, ", %s bytea%s", f->entries[i].tag, mand);
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

	PGresult *res;

	res = PQexec(db, buff);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		LOGF(L_ERR, STATUS_DB, "%s", PQerrorMessage(db));
		status = STATUS_DB;
		goto end;
	}

	//desending down into first child filter if it exists
	if (root->chld && (status = build_table(root->chld, buff))) {
		goto end;
	}

	// going to sibling filter
	if (root->next && (status = build_table(root->next, buff))) {
		goto end;
	}

	status = STATUS_OK;
end:
	PQclear(res);
	return status;
}

status_val dump_pq_build(struct ef_tree *root)
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

	// going to sibling filter
	if (root->next && (status = build_table(root->next, buff))) {
		goto end;
	}

	status = STATUS_OK;

end:
	free(buff);
	return status;
}

status_val dump_pq_dump(struct glist *lst)
{
	status_val status = STATUS_DB;
	const char *pe_blob_arr[PEBA_CAP] = { 0 };
	int pe_len_arr[PEBA_CAP] = { 0 };
	int pe_form_arr[PEBA_CAP] = { 0 };
	u_int peba_len = 0;

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

				off += sprintf(buff + off, ", $%d", peba_len + 1);
				pe_blob_arr[peba_len] =
					(char *const)p->entries[i].conv_data.blob.arr;
				pe_len_arr[peba_len] = p->entries[i].conv_data.blob.len;
				pe_form_arr[peba_len] = 1;
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

		PGresult *res = PQexecParams(db, buff, peba_len, NULL, pe_blob_arr,
									 pe_len_arr, pe_form_arr, 1);

		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			LOGF(L_ERR, STATUS_DB, "%s", PQerrorMessage(db));
			PQclear(res);
			goto end;
		}
		PQclear(res);
	}

	status = STATUS_OK;

end:
	free(buff);
	return status;
}

status_val dump_pq_close()
{
	dump_pq_dump(pc.cap_pkts); //syncing unwritten data
	sync_db_context();
	if (db) {
		PQfinish(db);
	}
	return STATUS_OK;
}

