/**
 * @file ext_filter.c
 * @brief Implementation of extended filter interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include <stddef.h>
#include <string.h>

#include "../include/glist.h"
#include "../include/filter.h"
#include "../include/fhmap.h"
#include "../include/ext_filter.h"

struct ext_filter *ext_filter_new(struct filter *f)
{
	status_val status = STATUS_OK;
	struct ext_filter *ef = calloc(1, sizeof(struct ext_filter));
	if (!ef) {
		LOG(L_CRIT, STATUS_OMEM);
		return NULL;
	}

	ef->active = true;

	ef->stash = stash_new();
	if (!ef->stash) {
		LOG(L_CRIT, STATUS_OMEM);
		free(ef);
		return NULL;
	}

	struct fhmap *hflt = fhmap_new(f->n_entries * FH_CAP_MULTIPLIER);
	if (!hflt) {
		LOG(L_CRIT, STATUS_OMEM);
		stash_free(ef->stash);
		free(ef);
		return NULL;
	}

	//putting all filter entries into hash map
	for (size_t i = 0; i < f->n_entries; i++) {
		status = fhmap_put(hflt, &f->entries[i]);
		if (status) {
			LOG(L_CRIT, status);
			ext_filter_free(ef);
			return NULL;
		}

		status = fhmap_put(pc.f_entries, &f->entries[i]);
		if (status) {
			LOG(L_CRIT, status);
			ext_filter_free(ef);
			return NULL;
		}
	}

	ef->filter = f;
	ef->mapped_filter = hflt;

	return ef;
}

void ext_filter_free(struct ext_filter *f)
{
	if (f) {
		if (f->filter->exit_filter) {
			f->filter->exit_filter();
		}

		fhmap_shallow_free(f->mapped_filter);
		stash_free(f->stash);
		free(f);
	}
}

