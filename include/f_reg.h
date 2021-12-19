#ifndef P_REGISTRY_H
#define P_REGISTRY_H

#include "../include/filter.h"

extern struct filter *filter_arr[];

void collect_packets(struct filter ***arr_ptr);

#endif
