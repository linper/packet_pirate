/**
 * @file stash.c
 * @brief Implementation of data structure, that stores all data in heap in one continiuos data block instead of many fragmented places
 * @author Linas Perkauskas
 * @date 2022-03-30
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>

#include "../include/stash.h"
#include <sys/types.h>

/**
 * @brief Creates stash_block struct
 * @param[in] *cap 	Capacity of new block
 * @return Pointer to created stash_block struct if successful, NULL otherwise  
 */
static struct stash_block *stash_block_new(size_t cap)
{
	struct stash_block *sb = calloc(1, sizeof(struct stash_block));
	if (!sb) {
		LOG(L_CRIT, STATUS_OMEM);
		return NULL;
	}

	sb->arr = calloc(cap, sizeof(u_char));
	if (!sb) {
		LOG(L_CRIT, STATUS_OMEM);
		free(sb);
		return NULL;
	}

	sb->cap = cap;

	return sb;
}

struct stash *stash_new()
{
	struct stash *st = calloc(1, sizeof(struct stash));
	if (!st) {
		LOG(L_CRIT, STATUS_OMEM);
		return NULL;
	}

	struct stash_block *sb = stash_block_new(STASH_DEFAULT_SIZE);
	if (!sb) {
		LOG(L_CRIT, STATUS_OMEM);
		free(st);
		return NULL;
	}

	st->first = sb;
	st->last = sb;
	st->block_count = 1;
	st->total_cap = STASH_DEFAULT_SIZE;

#ifdef DEVEL_STASH_DEBUG
	memset(st->gap_content, 0xFF, STASH_GAP);
#endif //DEVEL_STASH_DEBUG

	return st;
}

void *stash_alloc(struct stash *st, size_t size, const char *func, int line)
{
	(void)func;
	(void)line;

	size_t off = 0;
	struct stash_block *lsb = st->last;
	st->in_use = true;

	if (lsb->cap - lsb->used < size + STASH_GAP) {
		size_t new_tcap = 2 * st->total_cap;
		size_t new_cap = new_tcap - st->total_cap;

		while (new_cap < size + STASH_GAP) {
			new_tcap *= 2;
			new_cap = new_tcap - st->total_cap;
		}

		struct stash_block *new_lsb = stash_block_new(new_cap);
		if (!new_lsb) {
			LOG(L_CRIT, STATUS_OMEM);
			return NULL;
		}

		lsb->next = new_lsb;
		st->last = new_lsb;
		st->total_cap = new_tcap;
		st->block_count++;
	}

	off = st->last->used;

	st->last->used += size + STASH_GAP; //empty byte between blocks

#ifdef DEVEL_STASH_DEBUG
	stash_debug(st, func, line);

	struct stash_dbg *sdbg = calloc(1, sizeof(struct stash_dbg));
	sdbg->line = line;
	sdbg->func = func;
	sdbg->gap = st->last->arr + (st->last->used - STASH_GAP);
	memcpy(sdbg->gap, st->gap_content, STASH_GAP);
	sdbg->next = st->dbg;
	st->dbg = sdbg;
#endif //DEVEL_STASH_DEBUG

	return st->last->arr + off;
}

status_val stash_clear(struct stash *st)
{
#ifdef DEVEL_STASH_DEBUG
	STASH_DEBUG(st);

	if (st && st->dbg) {
		struct stash_dbg *next = NULL, *st_dbg = st->dbg;

		do {
			next = st_dbg->next;
			free(st_dbg);
		} while ((st_dbg = next));
	}

	st->dbg = NULL;
#endif //DEVEL_STASH_DEBUG

	/*We only want 1 stash block*/
	if (st->block_count > 1) {
		struct stash_block *sb2, *sb;
		/*Freeing second and rest of blocks*/
		sb = st->first;

		sb->arr = realloc(sb->arr, st->total_cap);
		if (!sb->arr) {
			LOG(L_CRIT, STATUS_OMEM);
			return STATUS_OMEM;
		}

		sb = sb->next;

		while (sb) {
			sb2 = sb->next;
			free(sb->arr);
			free(sb);
			sb = sb2;
		}
	}

	st->in_use = false;
	st->block_count = 1;
	st->last = st->first;
	st->first->next = NULL;
	st->first->cap = st->total_cap;
	st->first->used = 0;
	memset(st->first->arr, 0, st->total_cap);

	return STATUS_OK;
}

void stash_debug(struct stash *st, const char *func, int line)
{
	(void)st;
	(void)func;
	(void)line;
#ifdef DEVEL_STASH_DEBUG
	if (!st || !st->dbg) {
		return;
	}

	struct stash_dbg *st_dbg = st->dbg;
	int found = false;

	do {
		if (memcmp(st_dbg->gap, st->gap_content, STASH_GAP)) {
			if (!found) {
				found = true;
				printf("STASH DBG %p in %s at:[%d]\n", st, func, line);
			}

			printf(">>> %s at:[%d]", st_dbg->func, st_dbg->line);

			for (int i = 0; i < STASH_GAP; i++) {
				printf(" %2X", st->gap_content[i]);
			}
			printf(" =>");
			for (int i = 0; i < STASH_GAP; i++) {
				printf(" %2X", st_dbg->gap[i]);
			}
			printf("\n");
		}
	} while ((st_dbg = st_dbg->next));
#endif //DEVEL_STASH_DEBUG
}

void stash_free(struct stash *st)
{
	if (st) {
		struct stash_block *sb2, *sb = st->first;

#ifdef DEVEL_STASH_DEBUG
		STASH_DEBUG(st);

		if (st->dbg) {
			struct stash_dbg *next = NULL, *st_dbg = st->dbg;

			do {
				next = st_dbg->next;
				free(st_dbg);
			} while ((st_dbg = next));
		}
#endif //DEVEL_STASH_DEBUG

		while (sb) {
			sb2 = sb->next;
			free(sb->arr);
			free(sb);
			sb = sb2;
		}

		free(st);
	}
}

