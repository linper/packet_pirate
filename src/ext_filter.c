
#include "../include/ext_filter.h"


#define FHSTATUS_CAP_MULTIPLIER 2


struct ext_filter *ext_filter_new(struct filter *f)
{
    struct ext_filter *ef = calloc(1 , sizeof(struct ext_filter));
    if (!ef) {
        return NULL;
    }

    struct fhmap *hflt = fhmap_new(f->n_entries * FHSTATUS_CAP_MULTIPLIER);
    if (!hflt) {
        free(ef);
    return NULL;
    }

    for (size_t i = 0; i < f->n_entries; i++) { //putting all filter entries into hash map
        fhmap_put(hflt, &f->entries[i]);
    }

    ef->filter = f;
    ef->mapped_filter = hflt;

    return ef;
}


struct ext_filter *ext_filter_base()
{
    return calloc(1 , sizeof(struct ext_filter));
}

void ext_filter_free(struct ext_filter *f)
{
    fhmap_free(f->mapped_filter);
    free(f);

}


