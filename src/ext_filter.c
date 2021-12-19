
#include "../include/ext_filter.h"

#define FHSTATUS_CAP_MULTIPLIER 2

struct ext_filter *ext_filter_new(struct filter *f)
{
	status_val status = STATUS_OK;
	struct ext_filter *ef = calloc(1, sizeof(struct ext_filter));
	if (!ef) {
		LOG(L_CRIT, STATUS_OMEM);
		return NULL;
	}

	struct fhmap *hflt = fhmap_new(f->n_entries * FHSTATUS_CAP_MULTIPLIER);
	if (!hflt) {
		LOG(L_CRIT, STATUS_OMEM);
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
	}

	ef->filter = f;
	ef->mapped_filter = hflt;

	return ef;
}

struct ext_filter *ext_filter_base()
{
	struct ext_filter *f = calloc(1, sizeof(struct ext_filter));
	if (!f) {
		LOG(L_CRIT, STATUS_OMEM);
	}
	return f;
}

void ext_filter_free(struct ext_filter *f)
{
	fhmap_free(f->mapped_filter);
	free(f);
}

