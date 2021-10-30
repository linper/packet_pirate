#ifndef EXT_FILTER_H 
#define EXT_FILTER_H 

#include <stdio.h>
#include <stdlib.h>

#include "filter.h"
#include "filter_hmap.h"
#include "packet_registry.h"

struct ext_filter {
    struct filter *filter;
    struct fhmap *mapped_filter;
};

struct ext_filter *ext_filter_new(struct filter *f);

struct ext_filter *ext_filter_base();

void ext_filter_free(struct ext_filter *f);

#endif
